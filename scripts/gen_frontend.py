import os, textwrap

# File 1: Fix api.ts error handling
api_path = r"F:\SentinelAI\panel\src\lib\api.ts"

api_content = textwrap.dedent('''\
/**
 * SentinelAI API Client
 *
 * Centralized API communication layer for the dashboard.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1";

class ApiClient {
  private token: string | null = null;

  constructor() {
    if (typeof window !== "undefined") {
      this.token = localStorage.getItem("sentinelai_token");
    }
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== "undefined") {
      if (token) {
        localStorage.setItem("sentinelai_token", token);
      } else {
        localStorage.removeItem("sentinelai_token");
      }
    }
  }

  getToken(): string | null {
    return this.token;
  }

  clearToken() {
    this.setToken(null);
    if (typeof window !== "undefined") {
      localStorage.removeItem("sentinelai_refresh_token");
    }
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      if (response.status === 401) {
        this.clearToken();
        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }
      }
      const error = await response.json().catch(() => ({ detail: "Unknown error" }));
      // Handle Pydantic validation errors (detail is an array of objects)
      let message: string;
      if (Array.isArray(error.detail)) {
        message = error.detail.map((e: any) => e.msg || JSON.stringify(e)).join("; ");
      } else if (typeof error.detail === "string") {
        message = error.detail;
      } else if (typeof error.detail === "object" && error.detail !== null) {
        message = JSON.stringify(error.detail);
      } else {
        message = `API Error: ${response.status}`;
      }
      throw new Error(message);
    }

    return response.json();
  }

  // --- Auth ---
  async login(username: string, password: string) {
    const data = await this.request<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    this.setToken(data.access_token);
    if (typeof window !== "undefined") {
      localStorage.setItem("sentinelai_refresh_token", data.refresh_token);
    }
    return data;
  }

  async register(username: string, email: string, password: string, fullName?: string) {
    return this.request<{
      id: string;
      email: string;
      username: string;
      full_name: string | null;
      role: string;
    }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password, full_name: fullName }),
    });
  }

  // --- Dashboard ---
  async getDashboardStats() {
    return this.request<{
      agents: { total: number; online: number; isolated: number; os_distribution: Record<string, number> };
      alerts: { active: number; critical: number; last_24h: number; severity_breakdown: Record<string, number> };
      telemetry: { events_last_hour: number };
    }>("/dashboard/stats");
  }

  async getRecentAlerts() {
    return this.request<{ alerts: Alert[] }>("/dashboard/recent-alerts");
  }

  // --- Agents ---
  async getAgents(params?: { page?: number; status?: string; search?: string }) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.status) query.set("status", params.status);
    if (params?.search) query.set("search", params.search);
    return this.request<{ agents: Agent[]; total: number }>(`/agents?${query}`);
  }

  async getAgent(id: string) {
    return this.request<Agent>(`/agents/${id}`);
  }

  async sendAgentCommand(id: string, command: string, params: Record<string, unknown> = {}) {
    return this.request<CommandResponse>(`/agents/${id}/command`, {
      method: "POST",
      body: JSON.stringify({ command, parameters: params }),
    });
  }

  async decommissionAgent(id: string) {
    return this.request<{ status: string }>(`/agents/${id}`, {
      method: "DELETE",
    });
  }

  // --- Alerts ---
  async getAlerts(params?: { page?: number; severity?: string; status?: string }) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.severity) query.set("severity", params.severity);
    if (params?.status) query.set("status", params.status);
    return this.request<{ alerts: Alert[]; total: number }>(`/alerts?${query}`);
  }

  async updateAlert(id: string, data: { status?: string; assigned_to?: string }) {
    return this.request<Alert>(`/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  }

  async triggerAlertAnalysis(id: string) {
    return this.request<{ status: string }>(`/alerts/${id}/analyze`, {
      method: "POST",
    });
  }

  // --- AI Analysis ---
  async investigate(query: string, context: Record<string, unknown> = {}) {
    return this.request<{
      status: string;
      analysis: string;
      confidence: number;
      recommendations: string[];
      related_techniques: string[];
      sources: string[];
    }>("/analysis/investigate", {
      method: "POST",
      body: JSON.stringify({ query, context }),
    });
  }

  async threatLookup(type: string, value: string) {
    return this.request<{
      threat_level: string;
      details: Record<string, unknown>;
      recommendations: string[];
    }>("/analysis/threat-lookup", {
      method: "POST",
      body: JSON.stringify({ indicator_type: type, indicator_value: value }),
    });
  }
}

// Export singleton instance
export const api = new ApiClient();

// --- Types ---
export interface Agent {
  id: string;
  hostname: string;
  display_name: string | null;
  os_type: string;
  os_version: string;
  architecture: string;
  status: string;
  is_isolated: boolean;
  cpu_usage: number | null;
  memory_usage: number | null;
  disk_usage: number | null;
  uptime_seconds: number | null;
  internal_ip: string | null;
  external_ip: string | null;
  agent_version: string;
  last_heartbeat: string | null;
  registered_at: string;
  tags: Record<string, unknown> | null;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  status: string;
  detection_source: string;
  mitre_tactics: string[] | null;
  mitre_techniques: string[] | null;
  llm_analysis: string | null;
  llm_recommendation: string | null;
  detected_at: string;
  agent_id: string;
}

export interface CommandResponse {
  command_id: string;
  agent_id: string;
  command: string;
  status: string;
  output: string;
  data?: Record<string, unknown> | null;
  exit_code?: number | null;
}
''')

with open(api_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(api_content)
print(f"  OK {api_path}")

# File 2: Updated terminal page
term_path = r"F:\SentinelAI\panel\src\app\(authenticated)\terminal\page.tsx"

term_content = textwrap.dedent('''\
"use client";

import { useState, useEffect, useRef, KeyboardEvent } from "react";
import { Terminal, Send, Loader2, Trash2, Cpu, Network, Shield, HardDrive, Users, Clock, ListTree, ScanSearch } from "lucide-react";
import { api, Agent, CommandResponse } from "@/lib/api";

interface ShellLine {
  type: "input" | "output" | "error" | "system";
  text: string;
  ts: Date;
}

const QUICK_COMMANDS = [
  { label: "System Info", cmd: "sysinfo", icon: Cpu, desc: "Full system overview" },
  { label: "Processes", cmd: "ps", icon: ListTree, desc: "List running processes" },
  { label: "Connections", cmd: "netstat", icon: Network, desc: "Active network connections" },
  { label: "Open Ports", cmd: "scan_ports", icon: ScanSearch, desc: "Listening ports" },
  { label: "Software", cmd: "installed_software", icon: HardDrive, desc: "Installed programs" },
  { label: "Users", cmd: "users", icon: Users, desc: "Local user accounts" },
  { label: "Startup", cmd: "startup_items", icon: Clock, desc: "Startup programs" },
  { label: "Full Scan", cmd: "scan", icon: Shield, desc: "Complete system scan" },
];

export default function TerminalPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState<ShellLine[]>([
    { type: "system", text: "SentinelAI Remote Shell v0.2.0", ts: new Date() },
    { type: "system", text: "Select an endpoint to begin. Type commands or use Quick Scan buttons.", ts: new Date() },
  ]);
  const [sending, setSending] = useState(false);
  const [cmdHistory, setCmdHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await api.getAgents();
        setAgents(data.agents ?? []);
        const online = (data.agents ?? []).filter((a) => a.status === "online");
        if (online.length > 0) setSelectedAgent(online[0].id);
      } catch {}
    })();
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [history]);

  const selectedAgentInfo = agents.find((a) => a.id === selectedAgent);

  const executeCommand = async (cmdType: string, params: Record<string, unknown> = {}) => {
    if (!selectedAgent || sending) return;

    setSending(true);
    const displayCmd = cmdType === "shell" ? (params.command as string) : cmdType;

    setHistory((prev) => [...prev, { type: "input", text: displayCmd, ts: new Date() }]);

    try {
      const result: CommandResponse = await api.sendAgentCommand(selectedAgent, cmdType, params);
      if (result.status === "timeout") {
        setHistory((prev) => [...prev, {
          type: "error",
          text: "Timeout: " + (result.output || "Agent did not respond within 30 seconds."),
          ts: new Date(),
        }]);
      } else if (result.status === "error") {
        setHistory((prev) => [...prev, {
          type: "error",
          text: result.output || "Command returned an error.",
          ts: new Date(),
        }]);
      } else {
        setHistory((prev) => [...prev, {
          type: "output",
          text: result.output || "(no output)",
          ts: new Date(),
        }]);
      }
    } catch (err: any) {
      setHistory((prev) => [...prev, {
        type: "error",
        text: "Error: " + (err?.message || String(err) || "Command failed"),
        ts: new Date(),
      }]);
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  };

  const handleSend = async () => {
    if (!command.trim() || !selectedAgent || sending) return;
    const cmd = command.trim();
    setCmdHistory((prev) => [cmd, ...prev].slice(0, 50));
    setHistoryIdx(-1);
    setCommand("");
    await executeCommand("shell", { command: cmd });
  };

  const handleQuickCommand = async (cmdType: string) => {
    await executeCommand(cmdType);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleSend();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (cmdHistory.length > 0) {
        const next = Math.min(historyIdx + 1, cmdHistory.length - 1);
        setHistoryIdx(next);
        setCommand(cmdHistory[next]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx > 0) {
        const next = historyIdx - 1;
        setHistoryIdx(next);
        setCommand(cmdHistory[next]);
      } else {
        setHistoryIdx(-1);
        setCommand("");
      }
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-3rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-sentinel-400" />
            Remote Shell
          </h1>
          <p className="text-sm text-cyber-muted mt-1">Execute commands on connected endpoints</p>
        </div>

        {/* Agent picker */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <select
              value={selectedAgent}
              onChange={(e) => {
                setSelectedAgent(e.target.value);
                const agent = agents.find((a) => a.id === e.target.value);
                setHistory((prev) => [...prev, {
                  type: "system",
                  text: `Connected to ${agent?.hostname || "unknown"} (${agent?.os_type || "?"})`,
                  ts: new Date(),
                }]);
              }}
              className="input-terminal pr-8 text-xs min-w-[200px]"
            >
              <option value="">Select endpoint...</option>
              {agents.filter((a) => a.status === "online").map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname} ({a.os_type}) - {a.internal_ip}
                </option>
              ))}
            </select>
          </div>
          {selectedAgentInfo && (
            <span className="text-xs text-green-400 bg-green-500/10 px-2 py-1 rounded-full border border-green-500/20">
              {selectedAgentInfo.hostname}
            </span>
          )}
          <button
            onClick={() => setHistory([{ type: "system", text: "Terminal cleared.", ts: new Date() }])}
            className="p-2 text-cyber-muted hover:text-white hover:bg-cyber-hover rounded-lg transition-colors"
            title="Clear terminal"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Quick Scan Buttons */}
      {selectedAgent && (
        <div className="flex flex-wrap gap-2 mb-3">
          {QUICK_COMMANDS.map((qc) => (
            <button
              key={qc.cmd}
              onClick={() => handleQuickCommand(qc.cmd)}
              disabled={sending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-xs text-cyber-muted hover:text-sentinel-400 hover:border-sentinel-600/40 transition-all disabled:opacity-30"
              title={qc.desc}
            >
              <qc.icon className="w-3.5 h-3.5" />
              {qc.label}
            </button>
          ))}
        </div>
      )}

      {/* Terminal output */}
      <div
        ref={scrollRef}
        className="flex-1 bg-[#0a0a0a] border border-cyber-border rounded-t-xl p-4 overflow-y-auto font-mono text-sm"
        onClick={() => inputRef.current?.focus()}
      >
        {history.map((line, i) => (
          <div key={i} className="py-0.5">
            {line.type === "input" ? (
              <div className="flex items-start gap-2">
                <span className="text-sentinel-400 shrink-0">$</span>
                <span className="text-white">{line.text}</span>
              </div>
            ) : line.type === "error" ? (
              <span className="text-red-400">{line.text}</span>
            ) : line.type === "system" ? (
              <span className="text-cyber-muted italic">{line.text}</span>
            ) : (
              <pre className="text-cyber-text whitespace-pre-wrap break-all">{line.text}</pre>
            )}
          </div>
        ))}
        {sending && (
          <div className="flex items-center gap-2 py-1 text-cyber-muted">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span className="text-xs">Executing on {selectedAgentInfo?.hostname}...</span>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="flex items-center bg-[#0a0a0a] border border-t-0 border-cyber-border rounded-b-xl px-4 py-3">
        <span className="text-sentinel-400 mr-2 text-sm">$</span>
        <input
          ref={inputRef}
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={selectedAgent ? "Enter shell command..." : "Select an endpoint first..."}
          disabled={!selectedAgent || sending}
          className="flex-1 bg-transparent text-white text-sm placeholder-cyber-muted/50 focus:outline-none disabled:opacity-50"
          autoFocus
        />
        <button
          onClick={handleSend}
          disabled={!command.trim() || !selectedAgent || sending}
          className="p-1.5 bg-sentinel-600 hover:bg-sentinel-700 disabled:opacity-30 rounded-lg transition-colors ml-2"
        >
          <Send className="w-3.5 h-3.5 text-white" />
        </button>
      </div>
    </div>
  );
}
''')

os.makedirs(os.path.dirname(term_path), exist_ok=True)
with open(term_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(term_content)
print(f"  OK {term_path}")
