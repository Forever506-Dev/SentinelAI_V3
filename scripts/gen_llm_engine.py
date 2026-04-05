import os, textwrap

path = r"F:\SentinelAI\backend\app\services\llm_engine.py"

content = textwrap.dedent('''\
"""
LLM Engine Service  —  with OSINT Tool-Calling Loop

Multi-provider LLM integration for threat analysis and investigation.
The investigate() method now:
  1. Receives DB-enriched context (agent profile, telemetry, alerts)
  2. Gives the LLM a system prompt listing available OSINT tools
  3. Parses the LLM response for tool_calls requests
  4. Executes requested tools (whois, nslookup, ip_lookup, http_check)
  5. Feeds results back and re-prompts  (max 3 rounds)
  6. Returns the final structured analysis

Supports: Ollama (primary), OpenAI, Anthropic.
"""

import json
import re
import structlog

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

try:
    from langchain_ollama import ChatOllama
except ImportError:
    try:
        from langchain_ollama import OllamaLLM as ChatOllama
    except ImportError:
        try:
            from langchain_community.chat_models import ChatOllama
        except ImportError:
            ChatOllama = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

try:
    from langchain_anthropic import ChatAnthropic
except ImportError:
    ChatAnthropic = None

from app.core.config import settings
from app.services.osint_tools import execute_tool, TOOL_DESCRIPTIONS

logger = structlog.get_logger()

MAX_TOOL_ROUNDS = 3

# ─────────────────────────────────────────────────────────────────
# System prompts
# ─────────────────────────────────────────────────────────────────

THREAT_ANALYSIS_SYSTEM_PROMPT = """\
You are SentinelAI, an expert cybersecurity threat analyst AI. You analyze endpoint
telemetry data, security alerts, and indicators of compromise (IOCs) with the precision
of a senior SOC analyst.

Your responsibilities:
1. Analyze security events and classify threat severity accurately
2. Map threats to the MITRE ATT&CK framework (tactics, techniques, sub-techniques)
3. Provide actionable remediation recommendations
4. Identify attack chains and lateral movement patterns
5. Correlate events across multiple endpoints
6. Assess confidence levels honestly - state uncertainty when appropriate

Response format: Always respond with structured JSON containing:
- analysis: Detailed threat analysis narrative
- severity: critical | high | medium | low | informational
- confidence: 0.0 to 1.0
- mitre_techniques: Array of MITRE ATT&CK technique IDs (e.g., T1059.001)
- recommendations: Array of actionable steps
- ioc_indicators: Any extracted IOCs (IPs, domains, hashes)
- kill_chain_phase: reconnaissance | weaponization | delivery | exploitation | installation | c2 | actions_on_objectives
"""

INVESTIGATION_SYSTEM_PROMPT = """\
You are SentinelAI, an AI-powered cybersecurity investigation assistant. You help
security analysts investigate threats using endpoint telemetry, alerts, and OSINT tools.

## Context Data
You will receive enriched context containing:
- **Agent profiles**: hostname, OS, IP, CPU/memory, software inventory
- **Recent alerts**: severity, MITRE techniques, detection source
- **Recent telemetry**: processes, network connections, file events

## OSINT Tools
You have access to these network lookup tools. To use them, include a "tool_calls"
array in your JSON response. Each tool call is an object with "tool" and "args":

{tool_descriptions}

### Example tool_calls:
```json
{{
  "analysis": "I need to look up the IP address to determine its origin...",
  "confidence": 0.3,
  "tool_calls": [
    {{"tool": "whois", "args": {{"target": "example.com"}}}},
    {{"tool": "ip_lookup", "args": {{"ip": "8.8.8.8"}}}},
    {{"tool": "nslookup", "args": {{"domain": "example.com", "record_type": "MX"}}}},
    {{"tool": "http_check", "args": {{"url": "https://example.com"}}}}
  ]
}}
```

## Rules
- If agent data is provided, USE IT — analyze the real telemetry, alerts, and system info
- When the context contains installed software, check for known vulnerable versions
- When the context contains processes, look for suspicious parent-child chains
- When the context contains network connections, identify unusual destinations
- If you need external data (WHOIS, DNS, IP geo, site status), use tool_calls
- Be specific, cite evidence, flag uncertainties
- Recommend MITRE ATT&CK techniques when relevant

## Response format (JSON):
- analysis: Your investigation findings (use the actual agent data provided)
- confidence: 0.0 to 1.0
- recommendations: Array of next steps
- mitre_techniques: Relevant ATT&CK technique IDs
- sources: What data sources informed your analysis
- tool_calls: (optional) Array of OSINT tool requests if you need more data
"""


class LLMEngine:
    """Multi-provider LLM engine with OSINT tool-calling."""

    def __init__(self) -> None:
        self.provider = settings.LLM_PROVIDER
        self.llm = self._initialize_llm()
        self.str_parser = StrOutputParser()

    def _initialize_llm(self):
        match self.provider:
            case "openai":
                if ChatOpenAI is None:
                    raise ImportError("langchain-openai not installed")
                return ChatOpenAI(
                    model=settings.OPENAI_MODEL,
                    api_key=settings.OPENAI_API_KEY,
                    temperature=0.1,
                    max_tokens=4096,
                )
            case "anthropic":
                if ChatAnthropic is None:
                    raise ImportError("langchain-anthropic not installed")
                return ChatAnthropic(
                    model=settings.ANTHROPIC_MODEL,
                    api_key=settings.ANTHROPIC_API_KEY,
                    temperature=0.1,
                    max_tokens=4096,
                )
            case "ollama":
                if ChatOllama is None:
                    raise ImportError("langchain-ollama not installed. Run: pip install langchain-ollama")
                return ChatOllama(
                    base_url=settings.OLLAMA_BASE_URL,
                    model=settings.OLLAMA_MODEL,
                    temperature=0.1,
                )
            case _:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")

    # ─── JSON parsing ───────────────────────────────────────────

    def _safe_parse_json(self, text: str) -> dict:
        if isinstance(text, dict):
            return text
        raw = str(text).strip()
        # Strip markdown fences
        if "```" in raw:
            lines = raw.split("\\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            raw = "\\n".join(lines)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start:end])
                except json.JSONDecodeError:
                    pass
            return {
                "analysis": raw,
                "confidence": 0.3,
                "mitre_techniques": [],
                "recommendations": ["Manual review recommended"],
                "sources": [],
            }

    # ─── Tool-call extraction ───────────────────────────────────

    def _extract_tool_calls(self, parsed: dict) -> list[dict]:
        """Extract tool_calls from the parsed LLM response."""
        calls = parsed.get("tool_calls", [])
        if not isinstance(calls, list):
            return []
        valid = []
        for call in calls:
            if isinstance(call, dict) and "tool" in call:
                valid.append({
                    "tool": str(call["tool"]),
                    "args": call.get("args", {}),
                })
        return valid

    # ─── Investigation with tool loop ───────────────────────────

    async def investigate(self, query: str, context: dict) -> dict:
        """
        Investigation with automatic OSINT tool-calling loop.

        Flow:
        1. Build prompt with enriched context
        2. Send to LLM
        3. If response contains tool_calls → execute tools → re-prompt
        4. Repeat up to MAX_TOOL_ROUNDS times
        5. Return final analysis
        """
        system_prompt = INVESTIGATION_SYSTEM_PROMPT.replace(
            "{tool_descriptions}", TOOL_DESCRIPTIONS
        )

        # Build context string — truncate large fields intelligently
        context_str = json.dumps(context, indent=2, default=str)
        if len(context_str) > 12000:
            context_str = context_str[:12000] + "\\n... (truncated)"

        tools_used: list[dict] = []
        tool_results_text = ""

        for round_num in range(MAX_TOOL_ROUNDS + 1):
            human_msg = (
                f"Investigation Query: {query}\\n\\n"
                f"Enriched Context (agent data, alerts, telemetry):\\n{context_str}\\n"
            )
            if tool_results_text:
                human_msg += f"\\nTool Results from previous round:\\n{tool_results_text}\\n"
            human_msg += "\\nProvide your investigation findings as JSON."

            prompt = ChatPromptTemplate.from_messages([
                ("system", system_prompt),
                ("human", human_msg),
            ])

            chain = prompt | self.llm | self.str_parser

            try:
                raw_result = await chain.ainvoke({})
            except Exception as e:
                logger.error("LLM call failed", round=round_num, error=str(e))
                return {
                    "analysis": f"LLM call failed: {e}",
                    "confidence": 0.0,
                    "recommendations": ["Check Ollama is running"],
                    "mitre_techniques": [],
                    "sources": [],
                    "tools_used": tools_used,
                }

            parsed = self._safe_parse_json(raw_result)
            tool_calls = self._extract_tool_calls(parsed)

            if not tool_calls or round_num >= MAX_TOOL_ROUNDS:
                # Final answer — no more tools needed
                parsed["tools_used"] = tools_used
                logger.info(
                    "Investigation completed",
                    query=query[:80],
                    rounds=round_num + 1,
                    tools_used=len(tools_used),
                )
                return parsed

            # ── Execute requested tools ─────────────────────────
            logger.info(
                "LLM requested tools",
                round=round_num,
                tools=[c["tool"] for c in tool_calls],
            )
            round_results = []
            for call in tool_calls[:5]:  # max 5 tool calls per round
                result = await execute_tool(call["tool"], call.get("args", {}))
                entry = {
                    "tool": call["tool"],
                    "args": call.get("args", {}),
                    "result": result,
                }
                round_results.append(entry)
                tools_used.append(entry)

            tool_results_text = json.dumps(round_results, indent=2, default=str)
            if len(tool_results_text) > 6000:
                tool_results_text = tool_results_text[:6000] + "\\n... (truncated)"

        # Should not reach here but just in case
        parsed["tools_used"] = tools_used
        return parsed

    # ─── Alert analysis (unchanged) ─────────────────────────────

    async def analyze_alert(self, alert_data: dict) -> dict:
        prompt = ChatPromptTemplate.from_messages([
            ("system", THREAT_ANALYSIS_SYSTEM_PROMPT),
            ("human", (
                "Analyze the following security alert:\\n\\n"
                "Alert Title: {title}\\n"
                "Alert Description: {description}\\n"
                "Detection Source: {detection_source}\\n"
                "Agent OS: {os_type}\\n"
                "Raw Events: {raw_events}\\n"
                "Process Tree: {process_tree}\\n"
                "Network Context: {network_context}\\n\\n"
                "Provide a comprehensive threat analysis as JSON."
            )),
        ])

        chain = prompt | self.llm | self.str_parser

        try:
            raw = await chain.ainvoke({
                "title": alert_data.get("title", "Unknown"),
                "description": alert_data.get("description", "No description"),
                "detection_source": alert_data.get("detection_source", "unknown"),
                "os_type": alert_data.get("os_type", "unknown"),
                "raw_events": str(alert_data.get("raw_events", {}))[:3000],
                "process_tree": str(alert_data.get("process_tree", {}))[:1500],
                "network_context": str(alert_data.get("network_context", {}))[:1500],
            })
            result = self._safe_parse_json(raw)
            logger.info("Alert analysis completed", alert_title=alert_data.get("title"))
            return result
        except Exception as e:
            logger.error("LLM analysis failed", error=str(e))
            return {
                "analysis": f"Analysis failed: {e}",
                "severity": "unknown",
                "confidence": 0.0,
                "mitre_techniques": [],
                "recommendations": ["Manual analysis required"],
            }
''')

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"OK {path}")
