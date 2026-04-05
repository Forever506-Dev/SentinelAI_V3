import os, textwrap

# ── 1. Update api.ts — add OSINT methods ──────────────────────
api_path = r"F:\SentinelAI\panel\src\lib\api.ts"
with open(api_path, 'r', encoding='utf-8') as f:
    api_content = f.read()

# Add OSINT methods before the closing brace of the class
# Find the last method and add after it
osint_block = """
  // --- OSINT Tools ---
  async osintWhois(target: string) {
    return this.request<Record<string, unknown>>("/osint/whois", {
      method: "POST",
      body: JSON.stringify({ target }),
    });
  }

  async osintNslookup(domain: string, recordType: string = "A") {
    return this.request<Record<string, unknown>>("/osint/nslookup", {
      method: "POST",
      body: JSON.stringify({ domain, record_type: recordType }),
    });
  }

  async osintIpLookup(ip: string) {
    return this.request<Record<string, unknown>>("/osint/ip-lookup", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  }

  async osintHttpCheck(url: string) {
    return this.request<Record<string, unknown>>("/osint/http-check", {
      method: "POST",
      body: JSON.stringify({ url }),
    });
  }
"""

# Insert before the closing } of the class (before "// Export singleton")
marker = "}\n\n// Export singleton"
api_content = api_content.replace(marker, osint_block + "}\n\n// Export singleton")

with open(api_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(api_content)
print(f"OK {api_path}")


# ── 2. Rewrite analysis page ──────────────────────────────────
page_path = r"F:\SentinelAI\panel\src\app\(authenticated)\analysis\page.tsx"

page_content = textwrap.dedent('''\
"use client";

import { useState, useRef, useEffect } from "react";
import {
  Brain, Send, Shield, Search, Loader2, Target, Globe, Server,
  Wifi, WifiOff, MapPin, FileSearch, ChevronRight,
} from "lucide-react";
import { api } from "@/lib/api";

interface ToolResult {
  tool: string;
  args: Record<string, unknown>;
  result: Record<string, unknown>;
}

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  techniques?: string[];
  confidence?: number;
  sources?: string[];
  status?: string;
  toolsUsed?: ToolResult[];
}

const OSINT_TOOLS = [
  { id: "whois", label: "WHOIS", icon: FileSearch, placeholder: "Domain or IP (e.g. google.com)" },
  { id: "nslookup", label: "NS Lookup", icon: Server, placeholder: "Domain (e.g. google.com)" },
  { id: "ip_lookup", label: "IP Lookup", icon: MapPin, placeholder: "IP address (e.g. 8.8.8.8)" },
  { id: "http_check", label: "Site Check", icon: Globe, placeholder: "URL (e.g. https://example.com)" },
];

export default function AnalysisPage() {
  const [query, setQuery] = useState("");
  const [activeTab, setActiveTab] = useState<"investigate" | "osint">("investigate");
  const [osintTool, setOsintTool] = useState("whois");
  const [osintValue, setOsintValue] = useState("");
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: `Welcome to the SentinelAI Investigation Console.

I analyze threats using the Ollama LLM, LOLGlobs threat intelligence, and NVD vulnerability data.

**I now have full access to your endpoint data.** When you mention an agent hostname or IP, I automatically load its profile, alerts, telemetry, and installed software.

I can also run OSINT lookups during investigation:
• **WHOIS** — domain/IP registration
• **NS Lookup** — DNS records
• **IP Lookup** — geolocation + ASN
• **Site Check** — website up/down

Try asking:
• "Give me a vulnerability report for DESKTOP-U52HOUK"
• "Analyze suspicious network activity on 192.168.1.100"
• "What processes are running on my endpoint?"
• "Check if 45.33.32.156 is malicious"`,
      timestamp: new Date(),
    },
  ]);
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  // ── Investigation handler ────────────────────────────────────

  const handleInvestigate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim() || isLoading) return;

    const userMsg: Message = { role: "user", content: query, timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    const q = query;
    setQuery("");
    setIsLoading(true);

    try {
      const data = await api.investigate(q, {});
      const recs = data.recommendations?.length
        ? "\\n\\n**Recommendations:**\\n" + data.recommendations.map((r: string, i: number) => `${i + 1}. ${r}`).join("\\n")
        : "";
      const toolInfo = (data as any).tools_used?.length
        ? "\\n\\n**🔧 Tools Used:** " + (data as any).tools_used.map((t: any) => `${t.tool}(${JSON.stringify(t.args)})`).join(", ")
        : "";

      setMessages((prev) => [...prev, {
        role: "assistant",
        content: data.analysis + recs + toolInfo,
        timestamp: new Date(),
        techniques: data.related_techniques ?? [],
        confidence: data.confidence,
        sources: data.sources ?? [],
        status: data.status,
        toolsUsed: (data as any).tools_used,
      }]);
    } catch (err: any) {
      setMessages((prev) => [...prev, {
        role: "assistant",
        content: "⚠️ " + (err?.message || "Unknown error") + "\\n\\nMake sure Ollama is running.",
        timestamp: new Date(),
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  // ── OSINT direct handler ─────────────────────────────────────

  const handleOsint = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!osintValue.trim() || isLoading) return;

    const val = osintValue.trim();
    setIsLoading(true);
    setMessages((prev) => [...prev, {
      role: "user",
      content: `🔍 ${osintTool.toUpperCase()}: ${val}`,
      timestamp: new Date(),
    }]);
    setOsintValue("");

    try {
      let result: Record<string, unknown>;
      switch (osintTool) {
        case "whois":
          result = await api.osintWhois(val);
          break;
        case "nslookup":
          result = await api.osintNslookup(val);
          break;
        case "ip_lookup":
          result = await api.osintIpLookup(val);
          break;
        case "http_check":
          result = await api.osintHttpCheck(val);
          break;
        default:
          result = { error: "Unknown tool" };
      }

      // Format output
      let formatted: string;
      if (result.error) {
        formatted = `**Error:** ${result.error}`;
      } else if (osintTool === "http_check") {
        const status = result.status === "up" ? "🟢 UP" : "🔴 DOWN";
        formatted = `**${status}** — ${result.url}\\n` +
          `Status Code: ${result.status_code || "N/A"}\\n` +
          `Response Time: ${result.response_time_ms || "N/A"} ms\\n` +
          `Server: ${(result.headers as any)?.server || "Unknown"}\\n` +
          `TLS: ${result.tls ? "Yes" : "No"}`;
        if (result.final_url && result.final_url !== result.url) {
          formatted += `\\nRedirected to: ${result.final_url}`;
        }
      } else if (osintTool === "ip_lookup") {
        formatted = `**IP:** ${result.query || val}\\n` +
          `**Location:** ${result.city}, ${result.regionName}, ${result.country}\\n` +
          `**ISP:** ${result.isp}\\n` +
          `**Org:** ${result.org}\\n` +
          `**ASN:** ${result.as}\\n` +
          `**Hosting:** ${result.hosting ? "Yes" : "No"} | **Proxy/VPN:** ${result.proxy ? "Yes" : "No"}\\n` +
          `**Coords:** ${result.lat}, ${result.lon}`;
      } else if (osintTool === "nslookup") {
        const records = (result.records as string[]) || [];
        formatted = `**Domain:** ${result.domain}  **Type:** ${result.record_type}\\n` +
          (records.length ? records.map((r: string) => `  → ${r}`).join("\\n") : result.raw || "No records found") +
          (result.ttl ? `\\nTTL: ${result.ttl}s` : "");
      } else {
        // whois
        if (result.data && typeof result.data === "object") {
          formatted = Object.entries(result.data as Record<string, unknown>)
            .map(([k, v]) => `**${k}:** ${Array.isArray(v) ? v.join(", ") : v}`)
            .join("\\n");
        } else if (result.raw) {
          formatted = "```\\n" + String(result.raw).slice(0, 3000) + "\\n```";
        } else {
          formatted = JSON.stringify(result, null, 2);
        }
      }

      setMessages((prev) => [...prev, {
        role: "assistant",
        content: formatted,
        timestamp: new Date(),
      }]);
    } catch (err: any) {
      setMessages((prev) => [...prev, {
        role: "assistant",
        content: "⚠️ OSINT lookup failed: " + (err?.message || "Unknown error"),
        timestamp: new Date(),
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  // ── Render ───────────────────────────────────────────────────

  const currentOsintTool = OSINT_TOOLS.find((t) => t.id === osintTool)!;

  return (
    <div className="flex flex-col h-[calc(100vh-3rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Brain className="w-6 h-6 text-sentinel-400" />
            AI Investigation Console
          </h1>
          <p className="text-cyber-muted text-sm mt-1">Ollama LLM · LOLGlobs · NVD · OSINT Tools</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab("investigate")}
            className={"px-3 py-1.5 rounded-lg text-xs font-medium transition-all " +
              (activeTab === "investigate" ? "bg-sentinel-600 text-white" : "bg-cyber-card text-cyber-muted border border-cyber-border")}
          >
            <Brain className="w-3 h-3 inline mr-1" />Investigate
          </button>
          <button
            onClick={() => setActiveTab("osint")}
            className={"px-3 py-1.5 rounded-lg text-xs font-medium transition-all " +
              (activeTab === "osint" ? "bg-sentinel-600 text-white" : "bg-cyber-card text-cyber-muted border border-cyber-border")}
          >
            <Globe className="w-3 h-3 inline mr-1" />OSINT Tools
          </button>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-3 mb-3 pr-1">
        {messages.map((msg, i) => (
          <div key={i} className={"flex " + (msg.role === "user" ? "justify-end" : "justify-start")}>
            <div className={"max-w-4xl rounded-xl p-4 " +
              (msg.role === "user"
                ? "bg-sentinel-600/20 border border-sentinel-500/30 text-white"
                : "bg-cyber-card border border-cyber-border text-cyber-text")}
            >
              {msg.role === "assistant" && (
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-sentinel-400" />
                  <span className="text-xs font-medium text-sentinel-400">SentinelAI</span>
                  {msg.confidence != null && msg.confidence > 0 && (
                    <span className="text-[10px] text-cyber-muted bg-cyber-hover px-1.5 py-0.5 rounded-full">
                      Confidence: {(msg.confidence * 100).toFixed(0)}%
                    </span>
                  )}
                  {msg.toolsUsed && msg.toolsUsed.length > 0 && (
                    <span className="text-[10px] text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded-full">
                      🔧 {msg.toolsUsed.length} tool{msg.toolsUsed.length > 1 ? "s" : ""} used
                    </span>
                  )}
                </div>
              )}
              <div className="text-sm whitespace-pre-wrap leading-relaxed">{msg.content}</div>
              {msg.techniques && msg.techniques.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 mt-3 pt-3 border-t border-cyber-border">
                  <Target className="w-3 h-3 text-cyber-muted" />
                  <span className="text-[10px] text-cyber-muted">MITRE:</span>
                  {msg.techniques.map((t) => (
                    <span key={t} className="px-1.5 py-0.5 bg-sentinel-500/10 text-sentinel-400 rounded text-[10px] font-mono">{t}</span>
                  ))}
                </div>
              )}
              {msg.toolsUsed && msg.toolsUsed.length > 0 && (
                <details className="mt-3 pt-3 border-t border-cyber-border">
                  <summary className="text-[10px] text-cyber-muted cursor-pointer hover:text-white transition-colors">
                    View tool call details
                  </summary>
                  <div className="mt-2 space-y-1">
                    {msg.toolsUsed.map((t, j) => (
                      <div key={j} className="text-[10px] font-mono bg-[#0a0a0a] rounded p-2">
                        <span className="text-blue-400">{t.tool}</span>
                        <span className="text-cyber-muted">({JSON.stringify(t.args)})</span>
                        <ChevronRight className="w-2.5 h-2.5 inline mx-1 text-cyber-muted" />
                        <span className="text-green-400">{JSON.stringify(t.result).slice(0, 200)}</span>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
              <div className="flex items-center gap-2">
                <Loader2 className="w-4 h-4 text-sentinel-400 animate-spin" />
                <span className="text-xs text-cyber-muted">
                  {activeTab === "investigate" ? "Analyzing with LLM (may use OSINT tools)..." : "Running OSINT lookup..."}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input area */}
      {activeTab === "investigate" ? (
        <form onSubmit={handleInvestigate} className="relative">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask about threats, investigate endpoints, analyze vulnerabilities..."
            className="w-full bg-cyber-card border border-cyber-border rounded-xl pl-5 pr-14 py-4 text-sm text-white placeholder-cyber-muted focus:outline-none focus:border-sentinel-500 transition-colors"
          />
          <button
            type="submit"
            disabled={!query.trim() || isLoading}
            className="absolute right-3 top-1/2 -translate-y-1/2 p-2 bg-sentinel-600 hover:bg-sentinel-700 disabled:opacity-50 rounded-lg transition-colors"
          >
            <Send className="w-4 h-4 text-white" />
          </button>
        </form>
      ) : (
        <div className="space-y-2">
          {/* Tool selector row */}
          <div className="flex gap-2">
            {OSINT_TOOLS.map((tool) => (
              <button
                key={tool.id}
                onClick={() => setOsintTool(tool.id)}
                className={"flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all " +
                  (osintTool === tool.id
                    ? "bg-sentinel-600 text-white"
                    : "bg-cyber-card text-cyber-muted border border-cyber-border hover:border-sentinel-600/40")}
              >
                <tool.icon className="w-3.5 h-3.5" />
                {tool.label}
              </button>
            ))}
          </div>
          {/* Input */}
          <form onSubmit={handleOsint} className="flex gap-3">
            <input
              type="text"
              value={osintValue}
              onChange={(e) => setOsintValue(e.target.value)}
              placeholder={currentOsintTool.placeholder}
              className="flex-1 bg-cyber-card border border-cyber-border rounded-lg px-4 py-3 text-sm text-white placeholder-cyber-muted focus:outline-none focus:border-sentinel-500"
            />
            <button
              type="submit"
              disabled={!osintValue.trim() || isLoading}
              className="px-4 py-3 bg-sentinel-600 hover:bg-sentinel-700 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-2 text-white text-sm"
            >
              <currentOsintTool.icon className="w-4 h-4" />
              Lookup
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
''')

os.makedirs(os.path.dirname(page_path), exist_ok=True)
with open(page_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(page_content)
print(f"OK {page_path}")
