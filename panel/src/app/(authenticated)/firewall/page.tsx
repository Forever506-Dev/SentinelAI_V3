"use client";

import { useState, useEffect, useRef } from "react";
import {
  ShieldCheck, Flame, Plus, Trash2, Loader2, RefreshCw,
  Ban, Network, ArrowDownCircle, ArrowUpCircle, Monitor,
  Clock, CheckCircle, XCircle,
  ToggleLeft, ToggleRight, Camera, FileText,
  ClipboardCheck, AlertTriangle, Shield, Pencil,
  Search, Filter, X,
} from "lucide-react";
import {
  api,
  Agent,
  FirewallRulesResponse,
  RemediationActionRecord,
  TrackedFirewallRule,
  TrackedRulesFilterParams,
  PendingApproval,
} from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

/* ───────── Constants ───────── */

const TABS = [
  { id: "live", label: "Live Rules", icon: Flame },
  { id: "tracked", label: "Managed Rules", icon: ShieldCheck },
  { id: "approvals", label: "Approvals", icon: ClipboardCheck },
  { id: "history", label: "History", icon: Clock },
] as const;

type TabId = typeof TABS[number]["id"];

const PROFILE_OPTIONS = ["domain", "private", "public"] as const;

const ACTION_COLORS: Record<string, string> = {
  applied: "text-green-400 bg-green-500/10",
  failed: "text-red-400 bg-red-500/10",
  pending: "text-yellow-400 bg-yellow-500/10",
  rolled_back: "text-blue-400 bg-blue-500/10",
  approved: "text-green-400 bg-green-500/10",
  rejected: "text-red-400 bg-red-500/10",
  expired: "text-gray-400 bg-gray-500/10",
  auto_approved: "text-emerald-400 bg-emerald-500/10",
};

const ACTION_TYPE_LABELS: Record<string, string> = {
  firewall_add: "Add Rule",
  firewall_delete: "Delete Rule",
  firewall_edit: "Edit Rule",
  firewall_toggle: "Toggle Rule",
  firewall_block_ip: "Block IP",
  firewall_block_port: "Block Port",
  quarantine_set: "Quarantine",
};

/* ───────── Component ───────── */

export default function FirewallPage() {
  const { hasRole } = useAuth();

  /* ── State ── */
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [activeTab, setActiveTab] = useState<TabId>("live");

  // Live firewall rules
  const [rulesData, setRulesData] = useState<FirewallRulesResponse | null>(null);
  const [rulesLoading, setRulesLoading] = useState(false);

  // Live rules search & filters (client-side filtering)
  const [liveSearch, setLiveSearch] = useState("");
  const [liveFilterDirection, setLiveFilterDirection] = useState("");
  const [liveFilterAction, setLiveFilterAction] = useState("");
  const [liveFilterProfile, setLiveFilterProfile] = useState("");

  // Tracked/managed rules
  const [trackedRules, setTrackedRules] = useState<TrackedFirewallRule[]>([]);
  const [trackedTotal, setTrackedTotal] = useState(0);
  const [trackedLoading, setTrackedLoading] = useState(false);

  // Tracked rules filters (server-side)
  const [filterSearch, setFilterSearch] = useState("");
  const [filterDirection, setFilterDirection] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterEnabled, setFilterEnabled] = useState("");
  const [filterProfile, setFilterProfile] = useState("");
  const [trackedPage, setTrackedPage] = useState(1);
  const trackedPageSize = 50;

  // Add rule form
  const [showAddForm, setShowAddForm] = useState(false);
  const [formName, setFormName] = useState("");
  const [formDirection, setFormDirection] = useState<"inbound" | "outbound">("inbound");
  const [formAction, setFormAction] = useState<"block" | "allow">("block");
  const [formProtocol, setFormProtocol] = useState<"tcp" | "udp" | "any" | "icmp">("tcp");
  const [formPort, setFormPort] = useState("");
  const [formRemoteAddr, setFormRemoteAddr] = useState("");
  const [formProfiles, setFormProfiles] = useState<string[]>([]);
  const [formReason, setFormReason] = useState("");
  const [formSubmitting, setFormSubmitting] = useState(false);

  // Quick block
  const [blockIP, setBlockIP] = useState("");
  const [blockPort, setBlockPort] = useState("");
  const [blockProto, setBlockProto] = useState<"tcp" | "udp">("tcp");
  const [quickBlocking, setQuickBlocking] = useState(false);

  // Edit rule modal
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<{ id?: string; name: string; direction: string; action: string; protocol: string; port: string; remote_address: string; profiles: string[]; isTracked: boolean } | null>(null);
  const [editAction, setEditAction] = useState<string>("block");
  const [editProtocol, setEditProtocol] = useState<string>("tcp");
  const [editPort, setEditPort] = useState("");
  const [editRemoteAddr, setEditRemoteAddr] = useState("");
  const [editDirection, setEditDirection] = useState<string>("inbound");
  const [editProfiles, setEditProfiles] = useState<string[]>([]);
  const [editReason, setEditReason] = useState("");
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Approvals
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [approvalsLoading, setApprovalsLoading] = useState(false);

  // History
  const [history, setHistory] = useState<RemediationActionRecord[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Status messages
  const [statusMsg, setStatusMsg] = useState<{ type: "success" | "error"; text: string } | null>(null);

  /* ── Debounced filter reload for tracked rules (ref avoids stale closure) ── */
  const loadTrackedRef = useRef<((page?: number) => Promise<void>) | undefined>(undefined);

  useEffect(() => {
    if (activeTab !== "tracked" || !selectedAgent) return;
    const timer = setTimeout(() => {
      setTrackedPage(1);
      loadTrackedRef.current?.(1);
    }, 350);
    return () => clearTimeout(timer);
  }, [filterSearch, filterDirection, filterAction, filterEnabled, filterProfile, activeTab, selectedAgent]);

  const hasActiveFilters = filterSearch || filterDirection || filterAction || filterEnabled || filterProfile;

  const clearAllFilters = () => {
    setFilterSearch("");
    setFilterDirection("");
    setFilterAction("");
    setFilterEnabled("");
    setFilterProfile("");
    setTrackedPage(1);
  };

  const hasActiveLiveFilters = liveSearch || liveFilterDirection || liveFilterAction || liveFilterProfile;

  const clearAllLiveFilters = () => {
    setLiveSearch("");
    setLiveFilterDirection("");
    setLiveFilterAction("");
    setLiveFilterProfile("");
  };

  /** Parse a Windows profile string like "Domain, Private" into lowercase array */
  const parseProfileString = (profile: string): string[] => {
    if (!profile || profile === "—" || profile.toLowerCase() === "any" || profile.toLowerCase() === "all") return [];
    return profile.split(/[,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  };

  // Filtered live rules (client-side since they come from the agent)
  const filteredLiveRules = rulesData?.rules?.filter((rule: any) => {
    const name = (rule.Name || rule.name || "").toLowerCase();
    const dir = (rule.Direction || rule.direction || "").toLowerCase();
    const act = (rule.Action || rule.action || "").toLowerCase();
    const proto = (rule.Protocol || rule.protocol || "").toLowerCase();
    const port = String(rule.LocalPort || rule.local_port || "").toLowerCase();
    const remote = (rule.RemoteAddress || rule.remote_address || "").toLowerCase();
    const profile = (rule.Profile || rule.profile || "").toLowerCase();

    // Text search
    if (liveSearch.trim()) {
      const q = liveSearch.toLowerCase();
      if (!(name.includes(q) || proto.includes(q) || port.includes(q) || remote.includes(q))) return false;
    }
    // Direction filter
    if (liveFilterDirection) {
      const dirNorm = dir.includes("in") ? "inbound" : dir.includes("out") ? "outbound" : dir;
      if (dirNorm !== liveFilterDirection) return false;
    }
    // Action filter
    if (liveFilterAction) {
      const actNorm = (act.includes("block") || act.includes("drop")) ? "block" : act.includes("allow") ? "allow" : act;
      if (actNorm !== liveFilterAction) return false;
    }
    // Profile filter
    if (liveFilterProfile) {
      if (!profile.includes(liveFilterProfile)) return false;
    }
    return true;
  }) ?? [];

  /* ── Load agents ── */
  useEffect(() => {
    (async () => {
      try {
        const data = await api.getAgents();
        const list = (data.agents ?? []).filter((a) => a.status === "online");
        setAgents(list);
        if (list.length > 0) setSelectedAgent(list[0].id);
      } catch {}
    })();
  }, []);

  /* ── Load data when agent or tab changes ── */
  useEffect(() => {
    if (!selectedAgent) return;
    if (activeTab === "live") loadLiveRules();
    if (activeTab === "tracked") loadTrackedRules();
    if (activeTab === "history") loadHistory();
  }, [selectedAgent, activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (activeTab === "approvals") loadApprovals();
  }, [activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedAgentInfo = agents.find((a) => a.id === selectedAgent);

  /* ── API calls ── */

  const loadLiveRules = async () => {
    if (!selectedAgent) return;
    setRulesLoading(true);
    setStatusMsg(null);
    try {
      const data = await api.getFirewallRules(selectedAgent);
      setRulesData(data);
    } catch (err: any) {
      setStatusMsg({ type: "error", text: "Failed to load rules: " + (err?.message || String(err)) });
    } finally {
      setRulesLoading(false);
    }
  };

  const loadTrackedRules = async (page?: number) => {
    if (!selectedAgent) return;
    setTrackedLoading(true);
    try {
      const params: TrackedRulesFilterParams = {
        page: page ?? trackedPage,
        page_size: trackedPageSize,
      };
      if (filterSearch.trim()) params.search = filterSearch.trim();
      if (filterDirection) params.direction = filterDirection;
      if (filterAction) params.action = filterAction;
      if (filterEnabled) params.enabled = filterEnabled;
      if (filterProfile) params.profile = filterProfile;

      const data = await api.getTrackedFirewallRules(selectedAgent, params);
      setTrackedRules(data.rules || []);
      setTrackedTotal(data.total || 0);
    } catch (err: any) {
      setStatusMsg({ type: "error", text: "Failed to load tracked rules: " + (err?.message || String(err)) });
    } finally {
      setTrackedLoading(false);
    }
  };

  // Keep ref in sync so debounced effect always calls the latest version
  useEffect(() => { loadTrackedRef.current = loadTrackedRules; });

  const loadApprovals = async () => {
    setApprovalsLoading(true);
    try {
      const data = await api.getPendingApprovals();
      setPendingApprovals(data.approvals || []);
    } catch { /* ignore */ }
    setApprovalsLoading(false);
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const data = await api.getRemediationHistory({
        agent_id: selectedAgent || undefined,
      });
      setHistory(data.actions);
      setHistoryTotal(data.total);
    } catch {}
    setHistoryLoading(false);
  };

  const handleAddRule = async () => {
    if (!selectedAgent || formSubmitting) return;
    setFormSubmitting(true);
    setStatusMsg(null);
    try {
      const res = await api.addFirewallRule(selectedAgent, {
        name: formName || "custom-rule",
        direction: formDirection,
        action: formAction,
        protocol: formProtocol,
        port: formPort,
        remote_address: formRemoteAddr,
        profiles: formProfiles.length ? formProfiles : undefined,
        reason: formReason,
      });
      if (res.status === "completed") {
        setStatusMsg({ type: "success", text: `Rule "${formName || "custom-rule"}" added successfully.` });
        setShowAddForm(false);
        setFormName(""); setFormPort(""); setFormRemoteAddr(""); setFormReason(""); setFormProfiles([]);
        loadLiveRules();
      } else {
        setStatusMsg({ type: "error", text: res.output || "Failed to add rule." });
      }
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Failed to add rule." });
    } finally {
      setFormSubmitting(false);
    }
  };

  const handleDeleteRule = async (ruleName: string) => {
    if (!selectedAgent || !confirm(`Delete firewall rule "${ruleName}"?`)) return;
    setStatusMsg(null);
    try {
      const res = await api.deleteFirewallRule(selectedAgent, { name: ruleName });
      if (res.status === "completed") {
        setStatusMsg({ type: "success", text: `Rule "${ruleName}" deleted.` });
        loadLiveRules();
      } else {
        setStatusMsg({ type: "error", text: res.output || "Failed to delete rule." });
      }
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Failed to delete rule." });
    }
  };

  const handleDeleteTrackedRule = async (ruleId: string, ruleName: string) => {
    if (!selectedAgent || !confirm(`Delete tracked rule "${ruleName}"?`)) return;
    setStatusMsg(null);
    try {
      await api.deleteTrackedFirewallRule(selectedAgent, ruleId);
      setStatusMsg({ type: "success", text: `Tracked rule "${ruleName}" removed.` });
      loadTrackedRules();
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Failed to delete tracked rule." });
    }
  };

  /* ── Edit Rule Modal helpers ── */

  const openEditModal = (rule: {
    id?: string; name: string; direction: string; action: string;
    protocol: string; port: string; remote_address: string; profiles?: string[]; isTracked: boolean;
  }) => {
    setEditingRule({ ...rule, profiles: rule.profiles || [] });
    setEditAction(rule.action.toLowerCase().includes("block") || rule.action.toLowerCase().includes("drop") ? "block" : "allow");
    setEditProtocol(rule.protocol.toLowerCase() === "any" || rule.protocol === "—" ? "any" : rule.protocol.toLowerCase());
    setEditPort(!rule.port || rule.port.toLowerCase() === "any" || rule.port === "—" ? "" : rule.port);
    setEditRemoteAddr(!rule.remote_address || rule.remote_address.toLowerCase() === "any" || rule.remote_address === "—" ? "" : rule.remote_address);
    setEditDirection(rule.direction.toLowerCase().includes("in") ? "inbound" : "outbound");
    setEditProfiles(rule.profiles?.length ? [...rule.profiles] : []);
    setEditReason("");
    setEditModalOpen(true);
  };

  const handleEditSubmit = async () => {
    if (!selectedAgent || !editingRule || editSubmitting) return;
    setEditSubmitting(true);
    setStatusMsg(null);
    try {
      if (editingRule.isTracked && editingRule.id) {
        // Edit tracked/managed rule via the proper firewall API (with approval workflow)
        const res = await api.editTrackedFirewallRule(selectedAgent, editingRule.id, {
          action: editAction,
          protocol: editProtocol,
          port: editPort || undefined,
          remote_address: editRemoteAddr || undefined,
          direction: editDirection,
          profiles: editProfiles,
          reason: editReason || undefined,
        });
        if (res.status === "pending_approval") {
          setStatusMsg({ type: "success", text: `Edit requires approval. Approval ID: ${res.approval_id}` });
        } else if (res.status === "completed" || res.status === "applied") {
          setStatusMsg({ type: "success", text: `Rule "${editingRule.name}" updated successfully.` });
        } else if (res.status === "no_changes") {
          setStatusMsg({ type: "success", text: "No fields changed." });
        } else {
          setStatusMsg({ type: "error", text: res.output || `Update returned status: ${res.status}` });
        }
        await loadTrackedRules();
      } else {
        // For live (untracked) rules: use the edit endpoint (in-place netsh set rule)
        const res = await api.editFirewallRule(selectedAgent, {
          name: editingRule.name,
          direction: editDirection,
          action: editAction,
          protocol: editProtocol,
          port: editPort || undefined,
          remote_address: editRemoteAddr || undefined,
          profiles: editProfiles,
          reason: editReason || `Modified rule ${editingRule.name}`,
        });
        if (res.status === "completed") {
          setStatusMsg({ type: "success", text: `Rule "${editingRule.name}" modified successfully.` });
        } else {
          setStatusMsg({ type: "error", text: res.output || "Failed to modify rule." });
        }
        await loadLiveRules();
      }
      setEditModalOpen(false);
      setEditingRule(null);
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Failed to edit rule." });
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleBlockIP = async () => {
    if (!selectedAgent || !blockIP.trim() || quickBlocking) return;
    setQuickBlocking(true);
    setStatusMsg(null);
    try {
      const res = await api.blockIP(selectedAgent, blockIP.trim());
      if (res.status === "completed") {
        setStatusMsg({ type: "success", text: `IP ${blockIP} blocked.` });
        setBlockIP("");
        loadLiveRules();
      } else {
        setStatusMsg({ type: "error", text: res.output || "Failed to block IP." });
      }
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Failed to block IP." });
    } finally {
      setQuickBlocking(false);
    }
  };

  const handleBlockPort = async () => {
    if (!selectedAgent || !blockPort.trim() || quickBlocking) return;
    setQuickBlocking(true);
    setStatusMsg(null);
    try {
      const res = await api.blockPort(selectedAgent, blockPort.trim(), blockProto);
      if (res.status === "completed") {
        setStatusMsg({ type: "success", text: `Port ${blockPort}/${blockProto} blocked.` });
        setBlockPort("");
        loadLiveRules();
      } else {
        setStatusMsg({ type: "error", text: res.output || "Failed to block port." });
      }
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Failed to block port." });
    } finally {
      setQuickBlocking(false);
    }
  };

  const handleSnapshot = async () => {
    if (!selectedAgent) return;
    setStatusMsg(null);
    try {
      const res = await api.snapshotFirewallRules(selectedAgent);
      setStatusMsg({
        type: "success",
        text: `Snapshot captured: ${res.rules_count} rules, ${res.drift_count} drift(s) detected.`,
      });
      loadTrackedRules();
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Snapshot failed." });
    }
  };

  const handleToggleRule = async (rule: TrackedFirewallRule) => {
    if (!selectedAgent) return;
    try {
      await api.toggleFirewallRule(selectedAgent, rule.id, !rule.enabled);
      setStatusMsg({ type: "success", text: `Rule "${rule.name}" ${rule.enabled ? "disabled" : "enabled"}.` });
      loadTrackedRules();
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Toggle failed." });
    }
  };

  const handleApprovalDecision = async (approvalId: string, decision: "approve" | "reject") => {
    try {
      await api.decideApproval(approvalId, { decision });
      setStatusMsg({ type: "success", text: `Approval ${decision}d.` });
      loadApprovals();
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err?.message || "Decision failed." });
    }
  };

  /* ── Render ── */
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-sentinel-400" />
            Firewall &amp; Network Security
          </h1>
          <p className="text-sm text-cyber-muted mt-1">
            Manage firewall rules, review approvals, and monitor remediation actions
          </p>
        </div>

        {/* Agent picker */}
        <div className="flex items-center gap-3">
          <select
            value={selectedAgent}
            onChange={(e) => setSelectedAgent(e.target.value)}
            className="input-terminal text-xs min-w-[200px]"
          >
            <option value="">Select endpoint...</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.hostname} ({a.os_type}) {a.internal_ip ? `- ${a.internal_ip}` : ""}
              </option>
            ))}
          </select>
          {selectedAgentInfo && (
            <span className="text-xs text-green-400 bg-green-500/10 px-2 py-1 rounded-full border border-green-500/20 flex items-center gap-1">
              <Monitor className="w-3 h-3" />
              {selectedAgentInfo.hostname}
            </span>
          )}
        </div>
      </div>

      {/* Status message */}
      {statusMsg && (
        <div className={`p-3 rounded-lg border text-sm flex items-center gap-2 ${
          statusMsg.type === "success"
            ? "bg-green-500/10 border-green-500/30 text-green-400"
            : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>
          {statusMsg.type === "success" ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
          {statusMsg.text}
          <button onClick={() => setStatusMsg(null)} className="ml-auto text-cyber-muted hover:text-white">✕</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-cyber-border">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-all border-b-2 -mb-px ${
              activeTab === tab.id
                ? "text-sentinel-400 border-sentinel-500"
                : "text-cyber-muted border-transparent hover:text-white hover:border-cyber-border"
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {selectedAgent && (
        <>
          {/* ═══════════ TAB: Live Rules ═══════════ */}
          {activeTab === "live" && (
            <div className="space-y-4">
              {/* Quick Actions Row */}
              {hasRole("analyst") && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Block IP */}
                  <div className="bg-cyber-surface border border-cyber-border rounded-xl p-4">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                      <Ban className="w-4 h-4 text-red-400" />
                      Quick Block IP
                    </h3>
                    <div className="flex items-center gap-2">
                      <input
                        type="text" value={blockIP} onChange={(e) => setBlockIP(e.target.value)}
                        placeholder="e.g. 192.168.1.100"
                        className="flex-1 bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600"
                      />
                      <button onClick={handleBlockIP} disabled={!blockIP.trim() || quickBlocking}
                        className="px-4 py-2 bg-red-600/20 border border-red-500/40 text-red-300 rounded-lg text-sm font-medium hover:bg-red-600/30 disabled:opacity-30 transition-all flex items-center gap-1.5">
                        {quickBlocking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />}
                        Block
                      </button>
                    </div>
                  </div>

                  {/* Block Port */}
                  <div className="bg-cyber-surface border border-cyber-border rounded-xl p-4">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                      <Network className="w-4 h-4 text-orange-400" />
                      Quick Block Port
                    </h3>
                    <div className="flex items-center gap-2">
                      <input
                        type="text" value={blockPort} onChange={(e) => setBlockPort(e.target.value)}
                        placeholder="e.g. 4444"
                        className="flex-1 bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600"
                      />
                      <select value={blockProto} onChange={(e) => setBlockProto(e.target.value as "tcp" | "udp")}
                        className="bg-cyber-bg border border-cyber-border rounded-lg px-2 py-2 text-sm text-white">
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                      </select>
                      <button onClick={handleBlockPort} disabled={!blockPort.trim() || quickBlocking}
                        className="px-4 py-2 bg-orange-600/20 border border-orange-500/40 text-orange-300 rounded-lg text-sm font-medium hover:bg-orange-600/30 disabled:opacity-30 transition-all flex items-center gap-1.5">
                        {quickBlocking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Network className="w-3.5 h-3.5" />}
                        Block
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Active Firewall Rules */}
              <div className="bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-border">
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Flame className="w-5 h-5 text-sentinel-400" />
                    Active Firewall Rules
                    {rulesData && <span className="text-xs text-cyber-muted ml-2">({filteredLiveRules.length}{hasActiveLiveFilters ? ` / ${rulesData.total}` : ""} rules)</span>}
                  </h2>
                  <div className="flex items-center gap-2">
                    {hasRole("analyst") && (
                      <button onClick={() => setShowAddForm(!showAddForm)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-600/20 border border-sentinel-500/40 text-sentinel-300 rounded-lg text-xs font-medium hover:bg-sentinel-600/30 transition-all">
                        <Plus className="w-3.5 h-3.5" /> Add Rule
                      </button>
                    )}
                    <button onClick={loadLiveRules} disabled={rulesLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-xs hover:text-white transition-all disabled:opacity-30">
                      <RefreshCw className={`w-3.5 h-3.5 ${rulesLoading ? "animate-spin" : ""}`} /> Refresh
                    </button>
                  </div>
                </div>

                {/* Add rule form (collapsible) */}
                {showAddForm && (
                  <div className="px-5 py-4 border-b border-cyber-border bg-cyber-bg/50">
                    <h3 className="text-sm font-semibold text-white mb-3">New Firewall Rule</h3>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-3">
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Rule Name</label>
                        <input type="text" value={formName} onChange={(e) => setFormName(e.target.value)}
                          placeholder="block-suspicious-traffic"
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
                      </div>
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Direction</label>
                        <select value={formDirection} onChange={(e) => setFormDirection(e.target.value as any)}
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white mt-1">
                          <option value="inbound">Inbound</option>
                          <option value="outbound">Outbound</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Action</label>
                        <select value={formAction} onChange={(e) => setFormAction(e.target.value as any)}
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white mt-1">
                          <option value="block">Block</option>
                          <option value="allow">Allow</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Protocol</label>
                        <select value={formProtocol} onChange={(e) => setFormProtocol(e.target.value as any)}
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white mt-1">
                          <option value="tcp">TCP</option>
                          <option value="udp">UDP</option>
                          <option value="icmp">ICMP</option>
                          <option value="any">Any</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Port (optional)</label>
                        <input type="text" value={formPort} onChange={(e) => setFormPort(e.target.value)}
                          placeholder="e.g. 443"
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
                      </div>
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Remote Address</label>
                        <input type="text" value={formRemoteAddr} onChange={(e) => setFormRemoteAddr(e.target.value)}
                          placeholder="e.g. 10.0.0.0/8"
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase">Reason</label>
                        <input type="text" value={formReason} onChange={(e) => setFormReason(e.target.value)}
                          placeholder="Why are you adding this rule?"
                          className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
                      </div>
                      <div>
                        <label className="text-[10px] text-cyber-muted uppercase mb-1 block">Profiles</label>
                        <div className="flex items-center gap-3 mt-1">
                          {PROFILE_OPTIONS.map((p) => (
                            <label key={p} className="flex items-center gap-1.5 text-xs text-cyber-text cursor-pointer">
                              <input type="checkbox" checked={formProfiles.includes(p)}
                                onChange={(e) => setFormProfiles(e.target.checked ? [...formProfiles, p] : formProfiles.filter((x) => x !== p))}
                                className="rounded border-cyber-border bg-cyber-bg text-sentinel-500 focus:ring-sentinel-500 focus:ring-offset-0 w-3.5 h-3.5" />
                              {p.charAt(0).toUpperCase() + p.slice(1)}
                            </label>
                          ))}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={handleAddRule} disabled={formSubmitting}
                        className="flex items-center gap-1.5 px-4 py-2 bg-sentinel-600 text-white rounded-lg text-sm font-medium hover:bg-sentinel-700 disabled:opacity-30 transition-all">
                        {formSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                        Apply Rule
                      </button>
                      <button onClick={() => setShowAddForm(false)}
                        className="px-4 py-2 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-sm hover:text-white transition-all">
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {/* Live rules filter bar */}
                <div className="px-5 py-3 border-b border-cyber-border/50 bg-cyber-bg/30">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Search */}
                    <div className="relative flex-1 min-w-[200px] max-w-xs">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted pointer-events-none" />
                      <input
                        type="text" placeholder="Search rules..." value={liveSearch}
                        onChange={(e) => setLiveSearch(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-white placeholder:text-cyber-muted focus:outline-none focus:border-sentinel-500 transition-colors"
                      />
                    </div>
                    {/* Direction */}
                    <select value={liveFilterDirection} onChange={(e) => setLiveFilterDirection(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Directions</option>
                      <option value="inbound">Inbound</option>
                      <option value="outbound">Outbound</option>
                    </select>
                    {/* Action */}
                    <select value={liveFilterAction} onChange={(e) => setLiveFilterAction(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Actions</option>
                      <option value="block">Block</option>
                      <option value="allow">Allow</option>
                    </select>
                    {/* Profile */}
                    <select value={liveFilterProfile} onChange={(e) => setLiveFilterProfile(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Profiles</option>
                      {PROFILE_OPTIONS.map((p) => (
                        <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                      ))}
                    </select>
                    {/* Clear */}
                    {hasActiveLiveFilters && (
                      <button onClick={clearAllLiveFilters}
                        className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors">
                        <X className="w-3 h-3" /> Clear
                      </button>
                    )}
                  </div>
                </div>

                {/* Rules table */}
                <div className="overflow-x-auto">
                  {rulesLoading ? (
                    <div className="flex items-center justify-center py-12 text-cyber-muted">
                      <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading firewall rules from agent...
                    </div>
                  ) : rulesData && filteredLiveRules.length > 0 ? (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-[10px] text-cyber-muted uppercase border-b border-cyber-border">
                          <th className="px-5 py-3">Name</th>
                          <th className="px-3 py-3">Direction</th>
                          <th className="px-3 py-3">Action</th>
                          <th className="px-3 py-3">Protocol</th>
                          <th className="px-3 py-3">Local Port</th>
                          <th className="px-3 py-3">Remote Address</th>
                          <th className="px-3 py-3">Profile</th>
                          {hasRole("analyst") && <th className="px-3 py-3 text-right">Actions</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {filteredLiveRules.map((rule: any, i: number) => {
                          const name = rule.Name || rule.name || rule.chain || "—";
                          const dir = rule.Direction || rule.direction || "—";
                          const act = rule.Action || rule.action || "—";
                          const proto = rule.Protocol || rule.protocol || "—";
                          const port = rule.LocalPort || rule.local_port || "any";
                          const remote = rule.RemoteAddress || rule.remote_address || "any";
                          const profile = rule.Profile || rule.profile || "—";
                          const isBlock = act.toLowerCase().includes("block") || act.toLowerCase().includes("drop");
                          const isSentinelRule = typeof name === "string" && name.includes("SentinelAI");

                          return (
                            <tr key={i} className="border-b border-cyber-border/50 hover:bg-cyber-hover/30 transition-colors">
                              <td className="px-5 py-2.5 font-mono text-xs text-white truncate max-w-[200px]" title={name}>{name}</td>
                              <td className="px-3 py-2.5">
                                <span className="flex items-center gap-1 text-xs">
                                  {dir.toLowerCase().includes("in") ? <ArrowDownCircle className="w-3 h-3 text-blue-400" /> : <ArrowUpCircle className="w-3 h-3 text-purple-400" />}
                                  {dir}
                                </span>
                              </td>
                              <td className="px-3 py-2.5">
                                <span className={`text-xs px-2 py-0.5 rounded-full ${isBlock ? "bg-red-500/10 text-red-400" : "bg-green-500/10 text-green-400"}`}>{act}</span>
                              </td>
                              <td className="px-3 py-2.5 text-xs text-cyber-text">{proto}</td>
                              <td className="px-3 py-2.5 text-xs text-cyber-text font-mono">{port}</td>
                              <td className="px-3 py-2.5 text-xs text-cyber-text font-mono truncate max-w-[120px]" title={remote}>{remote}</td>
                              <td className="px-3 py-2.5 text-xs text-cyber-muted">{profile}</td>
                              {hasRole("analyst") && (
                                <td className="px-3 py-2.5 text-right">
                                  <div className="flex items-center gap-1 justify-end">
                                    <button onClick={() => openEditModal({
                                      name, direction: dir, action: act, protocol: proto,
                                      port: String(port).toLowerCase() === "any" ? "" : String(port),
                                      remote_address: String(remote).toLowerCase() === "any" ? "" : String(remote),
                                      profiles: parseProfileString(profile),
                                      isTracked: false,
                                    })} className="p-1 text-cyber-muted hover:text-sentinel-400 transition-colors" title="Edit Rule">
                                      <Pencil className="w-3.5 h-3.5" />
                                    </button>
                                    {isSentinelRule && (
                                      <button onClick={() => handleDeleteRule(name)}
                                        className="p-1 text-cyber-muted hover:text-red-400 transition-colors" title="Delete">
                                        <Trash2 className="w-3.5 h-3.5" />
                                      </button>
                                    )}
                                  </div>
                                </td>
                              )}
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  ) : rulesData ? (
                    <div className="flex flex-col items-center justify-center py-12 text-cyber-muted">
                      <ShieldCheck className="w-8 h-8 mb-2 opacity-30" />
                      {hasActiveLiveFilters ? (
                        <>
                          <span className="text-sm">No rules match filters</span>
                          <button onClick={clearAllLiveFilters} className="text-xs mt-2 text-sentinel-400 hover:underline">Clear all filters</button>
                        </>
                      ) : (
                        <span className="text-sm">No firewall rules returned</span>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center justify-center py-12 text-cyber-muted text-sm">
                      Select an endpoint and click Refresh to load firewall rules.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ═══════════ TAB: Managed/Tracked Rules ═══════════ */}
          {activeTab === "tracked" && (
            <div className="space-y-4">
              <div className="bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-border">
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Shield className="w-5 h-5 text-sentinel-400" />
                    Managed Rules
                    <span className="text-xs text-cyber-muted ml-2">({trackedTotal})</span>
                  </h2>
                  <div className="flex items-center gap-2">
                    {hasRole("analyst") && (
                      <button onClick={handleSnapshot}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/20 border border-blue-500/40 text-blue-300 rounded-lg text-xs font-medium hover:bg-blue-600/30 transition-all">
                        <Camera className="w-3.5 h-3.5" /> Snapshot &amp; Drift
                      </button>
                    )}
                    <button onClick={() => loadTrackedRules()} disabled={trackedLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-xs hover:text-white transition-all disabled:opacity-30">
                      <RefreshCw className={`w-3.5 h-3.5 ${trackedLoading ? "animate-spin" : ""}`} /> Refresh
                    </button>
                  </div>
                </div>

                {/* ── Filter Bar ── */}
                <div className="px-5 py-3 border-b border-cyber-border/50 bg-cyber-bg/30">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Search */}
                    <div className="relative flex-1 min-w-[200px] max-w-xs">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted pointer-events-none" />
                      <input
                        type="text"
                        placeholder="Search rules..."
                        value={filterSearch}
                        onChange={(e) => setFilterSearch(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-white placeholder:text-cyber-muted focus:outline-none focus:border-sentinel-500 transition-colors"
                      />
                    </div>
                    {/* Direction */}
                    <select value={filterDirection} onChange={(e) => setFilterDirection(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Directions</option>
                      <option value="inbound">Inbound</option>
                      <option value="outbound">Outbound</option>
                    </select>
                    {/* Action */}
                    <select value={filterAction} onChange={(e) => setFilterAction(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Actions</option>
                      <option value="block">Block</option>
                      <option value="allow">Allow</option>
                    </select>
                    {/* Enabled */}
                    <select value={filterEnabled} onChange={(e) => setFilterEnabled(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Status</option>
                      <option value="true">Active</option>
                      <option value="false">Disabled</option>
                    </select>
                    {/* Profile */}
                    <select value={filterProfile} onChange={(e) => setFilterProfile(e.target.value)}
                      className="px-2.5 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-sentinel-500">
                      <option value="">All Profiles</option>
                      {PROFILE_OPTIONS.map((p) => (
                        <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                      ))}
                    </select>
                    {/* Clear */}
                    {hasActiveFilters && (
                      <button onClick={clearAllFilters}
                        className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors">
                        <X className="w-3 h-3" /> Clear
                      </button>
                    )}
                  </div>
                </div>

                <div className="overflow-x-auto">
                  {trackedLoading ? (
                    <div className="flex items-center justify-center py-12 text-cyber-muted">
                      <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading managed rules...
                    </div>
                  ) : trackedRules.length > 0 ? (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-[10px] text-cyber-muted uppercase border-b border-cyber-border">
                          <th className="px-5 py-3">Name</th>
                          <th className="px-3 py-3">Dir</th>
                          <th className="px-3 py-3">Action</th>
                          <th className="px-3 py-3">Proto</th>
                          <th className="px-3 py-3">Port</th>
                          <th className="px-3 py-3">Remote</th>
                          <th className="px-3 py-3">Profiles</th>
                          <th className="px-3 py-3">Version</th>
                          <th className="px-3 py-3">Status</th>
                          {hasRole("analyst") && <th className="px-3 py-3 text-right">Actions</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {trackedRules.map((rule) => (
                          <tr key={rule.id} className="border-b border-cyber-border/50 hover:bg-cyber-hover/30 transition-colors">
                            <td className="px-5 py-2.5 font-mono text-xs text-white">{rule.name}</td>
                            <td className="px-3 py-2.5 text-xs">
                              {rule.direction === "inbound" ? <ArrowDownCircle className="w-3 h-3 text-blue-400 inline" /> : <ArrowUpCircle className="w-3 h-3 text-purple-400 inline" />}
                              {" "}{rule.direction}
                            </td>
                            <td className="px-3 py-2.5">
                              <span className={`text-xs px-2 py-0.5 rounded-full ${rule.action === "block" ? "bg-red-500/10 text-red-400" : "bg-green-500/10 text-green-400"}`}>{rule.action}</span>
                            </td>
                            <td className="px-3 py-2.5 text-xs text-cyber-text">{rule.protocol}</td>
                            <td className="px-3 py-2.5 text-xs font-mono text-cyber-text">{rule.port || "any"}</td>
                            <td className="px-3 py-2.5 text-xs font-mono text-cyber-text">{rule.remote_address || "any"}</td>
                            <td className="px-3 py-2.5">
                              <div className="flex flex-wrap gap-1">
                                {(rule.profiles && rule.profiles.length > 0) ? rule.profiles.map((p: string) => (
                                  <span key={p} className="text-[10px] px-1.5 py-0.5 bg-indigo-500/10 text-indigo-300 rounded border border-indigo-500/20">
                                    {p}
                                  </span>
                                )) : (
                                  <span className="text-[10px] text-cyber-muted">any</span>
                                )}
                              </div>
                            </td>
                            <td className="px-3 py-2.5 text-xs text-cyber-muted">v{rule.current_version}</td>
                            <td className="px-3 py-2.5">
                              <div className="flex items-center gap-2">
                                {rule.enabled ? (
                                  <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Active</span>
                                ) : (
                                  <span className="text-xs text-gray-500 flex items-center gap-1"><XCircle className="w-3 h-3" /> Disabled</span>
                                )}
                                {rule.drift_detected && (
                                  <span className="text-[10px] text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded-full border border-yellow-500/20">
                                    DRIFT
                                  </span>
                                )}
                              </div>
                            </td>
                            {hasRole("analyst") && (
                              <td className="px-3 py-2.5 text-right flex items-center gap-1 justify-end">
                                <button onClick={() => openEditModal({
                                  id: rule.id, name: rule.name, direction: rule.direction,
                                  action: rule.action, protocol: rule.protocol,
                                  port: rule.port || "", remote_address: rule.remote_address || "",
                                  profiles: rule.profiles || [],
                                  isTracked: true,
                                })} title="Edit"
                                  className="p-1 text-cyber-muted hover:text-sentinel-400 transition-colors">
                                  <Pencil className="w-3.5 h-3.5" />
                                </button>
                                <button onClick={() => handleToggleRule(rule)} title={rule.enabled ? "Disable" : "Enable"}
                                  className="p-1 text-cyber-muted hover:text-white transition-colors">
                                  {rule.enabled ? <ToggleRight className="w-4 h-4 text-green-400" /> : <ToggleLeft className="w-4 h-4" />}
                                </button>
                                {hasRole("admin") && (
                                  <button onClick={() => handleDeleteTrackedRule(rule.id, rule.name)} title="Delete"
                                    className="p-1 text-cyber-muted hover:text-red-400 transition-colors">
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                )}
                              </td>
                            )}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12 text-cyber-muted">
                      <FileText className="w-8 h-8 mb-2 opacity-30" />
                      {hasActiveFilters ? (
                        <>
                          <span className="text-sm">No rules match filters</span>
                          <button onClick={clearAllFilters} className="text-xs mt-2 text-sentinel-400 hover:underline">Clear all filters</button>
                        </>
                      ) : (
                        <>
                          <span className="text-sm">No managed rules yet</span>
                          <span className="text-xs mt-1">Take a snapshot to start tracking firewall rules</span>
                        </>
                      )}
                    </div>
                  )}
                </div>

                {/* ── Pagination ── */}
                {trackedTotal > trackedPageSize && (
                  <div className="flex items-center justify-between px-5 py-3 border-t border-cyber-border/50 bg-cyber-bg/20">
                    <span className="text-xs text-cyber-muted">
                      Showing {(trackedPage - 1) * trackedPageSize + 1}–{Math.min(trackedPage * trackedPageSize, trackedTotal)} of {trackedTotal}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <button disabled={trackedPage <= 1} onClick={() => { setTrackedPage(trackedPage - 1); loadTrackedRules(trackedPage - 1); }}
                        className="px-2.5 py-1 text-xs bg-cyber-surface border border-cyber-border rounded text-cyber-muted hover:text-white disabled:opacity-30 transition-colors">
                        Prev
                      </button>
                      <span className="text-xs text-cyber-muted px-2">Page {trackedPage} / {Math.ceil(trackedTotal / trackedPageSize)}</span>
                      <button disabled={trackedPage * trackedPageSize >= trackedTotal} onClick={() => { setTrackedPage(trackedPage + 1); loadTrackedRules(trackedPage + 1); }}
                        className="px-2.5 py-1 text-xs bg-cyber-surface border border-cyber-border rounded text-cyber-muted hover:text-white disabled:opacity-30 transition-colors">
                        Next
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ═══════════ TAB: Approvals ═══════════ */}
          {activeTab === "approvals" && (
            <div className="space-y-4">
              <div className="bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-border">
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <ClipboardCheck className="w-5 h-5 text-sentinel-400" />
                    Pending Approvals
                    {pendingApprovals.length > 0 && (
                      <span className="px-1.5 py-0.5 text-[10px] font-bold bg-red-600 text-white rounded-full">
                        {pendingApprovals.length}
                      </span>
                    )}
                  </h2>
                  <button onClick={loadApprovals} disabled={approvalsLoading}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-xs hover:text-white transition-all disabled:opacity-30">
                    <RefreshCw className={`w-3.5 h-3.5 ${approvalsLoading ? "animate-spin" : ""}`} /> Refresh
                  </button>
                </div>

                {approvalsLoading ? (
                  <div className="flex items-center justify-center py-12 text-cyber-muted">
                    <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading approvals...
                  </div>
                ) : pendingApprovals.length > 0 ? (
                  <div className="divide-y divide-cyber-border">
                    {pendingApprovals.map((approval) => (
                      <div key={approval.id} className="px-5 py-4 hover:bg-cyber-hover/30 transition-colors">
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <AlertTriangle className="w-4 h-4 text-yellow-400" />
                              <span className="text-sm font-medium text-white">
                                {approval.action_type ? ACTION_TYPE_LABELS[approval.action_type] || approval.action_type : "Remediation Action"}
                              </span>
                              {approval.agent_hostname && (
                                <span className="text-xs text-cyber-muted">on {approval.agent_hostname}</span>
                              )}
                            </div>
                            <p className="text-xs text-cyber-muted ml-6">
                              Requested by <span className="text-white">{approval.requester_username || "unknown"}</span>
                              {approval.request_reason && <> — {approval.request_reason}</>}
                            </p>
                            <p className="text-[10px] text-cyber-muted ml-6 mt-1">
                              Expires: {approval.expires_at ? new Date(approval.expires_at).toLocaleString() : "N/A"}
                            </p>
                          </div>
                          {hasRole("admin") && (
                            <div className="flex items-center gap-2">
                              <button onClick={() => handleApprovalDecision(approval.id, "approve")}
                                className="px-3 py-1.5 bg-green-600/20 border border-green-500/40 text-green-300 rounded-lg text-xs font-medium hover:bg-green-600/30 transition-all flex items-center gap-1">
                                <CheckCircle className="w-3 h-3" /> Approve
                              </button>
                              <button onClick={() => handleApprovalDecision(approval.id, "reject")}
                                className="px-3 py-1.5 bg-red-600/20 border border-red-500/40 text-red-300 rounded-lg text-xs font-medium hover:bg-red-600/30 transition-all flex items-center gap-1">
                                <XCircle className="w-3 h-3" /> Reject
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-cyber-muted">
                    <CheckCircle className="w-8 h-8 mb-2 opacity-30" />
                    <span className="text-sm">No pending approvals</span>
                    <span className="text-xs mt-1">All remediation actions are up to date</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ═══════════ TAB: History ═══════════ */}
          {activeTab === "history" && (
            <div className="space-y-4">
              <div className="bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-border">
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Clock className="w-5 h-5 text-sentinel-400" />
                    Remediation History
                    {historyTotal > 0 && <span className="text-xs text-cyber-muted ml-2">({historyTotal})</span>}
                  </h2>
                  <button onClick={loadHistory} disabled={historyLoading}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-xs hover:text-white transition-all disabled:opacity-30">
                    <RefreshCw className={`w-3.5 h-3.5 ${historyLoading ? "animate-spin" : ""}`} /> Refresh
                  </button>
                </div>

                {historyLoading ? (
                  <div className="flex items-center justify-center py-12 text-cyber-muted">
                    <Loader2 className="w-4 h-4 animate-spin mr-2" /> Loading history...
                  </div>
                ) : history.length > 0 ? (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-[10px] text-cyber-muted uppercase border-b border-cyber-border">
                        <th className="px-5 py-3">Time</th>
                        <th className="px-3 py-3">Type</th>
                        <th className="px-3 py-3">Details</th>
                        <th className="px-3 py-3">Status</th>
                        <th className="px-3 py-3">Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((a) => (
                        <tr key={a.id} className="border-b border-cyber-border/50">
                          <td className="px-5 py-2.5 text-xs text-cyber-muted whitespace-nowrap">
                            {a.created_at ? new Date(a.created_at).toLocaleString() : "—"}
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="text-xs px-2 py-0.5 rounded bg-cyber-bg text-cyber-text">
                              {ACTION_TYPE_LABELS[a.action_type] || a.action_type}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-xs text-cyber-text font-mono">
                            {a.rule_name || ""} {a.protocol ? `${a.protocol}` : ""} {a.port ? `:${a.port}` : ""} {a.remote_address ? `→ ${a.remote_address}` : ""}
                          </td>
                          <td className="px-3 py-2.5">
                            <span className={`text-xs px-2 py-0.5 rounded-full ${ACTION_COLORS[a.status] || "text-cyber-muted bg-cyber-bg"}`}>
                              {a.status}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-xs text-cyber-muted truncate max-w-[200px]" title={a.reason || ""}>
                            {a.reason || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="flex items-center justify-center py-8 text-cyber-muted text-sm">
                    No remediation actions recorded yet.
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}

      {/* ═══════════ EDIT RULE MODAL ═══════════ */}
      {editModalOpen && editingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-cyber-surface border border-cyber-border rounded-2xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-border">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Pencil className="w-4 h-4 text-sentinel-400" />
                Edit Rule: <span className="font-mono text-sentinel-300 truncate max-w-[200px]">{editingRule.name}</span>
              </h3>
              <button onClick={() => { setEditModalOpen(false); setEditingRule(null); }}
                className="text-cyber-muted hover:text-white transition-colors text-lg">✕</button>
            </div>

            {/* Modal Body */}
            <div className="px-6 py-5 space-y-4">
              {/* Direction */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider">Direction</label>
                <select value={editDirection} onChange={(e) => setEditDirection(e.target.value)}
                  className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sentinel-600 mt-1">
                  <option value="inbound">Inbound</option>
                  <option value="outbound">Outbound</option>
                </select>
              </div>

              {/* Action */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider">Action</label>
                <select value={editAction} onChange={(e) => setEditAction(e.target.value)}
                  className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sentinel-600 mt-1">
                  <option value="allow">Allow</option>
                  <option value="block">Block</option>
                </select>
              </div>

              {/* Protocol */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider">Protocol</label>
                <select value={editProtocol} onChange={(e) => setEditProtocol(e.target.value)}
                  className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sentinel-600 mt-1">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                  <option value="any">Any</option>
                </select>
              </div>

              {/* Local Port */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider">Local Port</label>
                <input type="text" value={editPort} onChange={(e) => setEditPort(e.target.value)}
                  placeholder="e.g. 443 or 8000-9000 (blank = any)"
                  className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
              </div>

              {/* Remote Address */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider">Remote Address</label>
                <input type="text" value={editRemoteAddr} onChange={(e) => setEditRemoteAddr(e.target.value)}
                  placeholder="e.g. 10.0.0.0/8 or 192.168.1.1 (blank = any)"
                  className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
              </div>

              {/* Profiles */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider mb-2 block">Profiles (Windows)</label>
                <div className="flex items-center gap-4 mt-1">
                  {PROFILE_OPTIONS.map((p) => (
                    <label key={p} className="flex items-center gap-1.5 text-sm text-cyber-text cursor-pointer select-none">
                      <input type="checkbox" checked={editProfiles.includes(p)}
                        onChange={(e) => setEditProfiles(e.target.checked ? [...editProfiles, p] : editProfiles.filter((x) => x !== p))}
                        className="rounded border-cyber-border bg-cyber-bg text-sentinel-500 focus:ring-sentinel-500 focus:ring-offset-0 w-4 h-4" />
                      {p.charAt(0).toUpperCase() + p.slice(1)}
                    </label>
                  ))}
                </div>
                <p className="text-[10px] text-cyber-muted mt-1.5">Leave unchecked for &quot;any&quot; profile. Ignored on Linux agents.</p>
              </div>

              {/* Reason */}
              <div>
                <label className="text-[10px] text-cyber-muted uppercase tracking-wider">Reason for change</label>
                <input type="text" value={editReason} onChange={(e) => setEditReason(e.target.value)}
                  placeholder="Optional: explain why you're modifying this rule"
                  className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-sm text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600 mt-1" />
              </div>

              {editingRule.isTracked && !hasRole("admin") && (
                <div className="flex items-start gap-2 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-xs text-yellow-300">
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>This change requires admin approval before it takes effect on the endpoint.</span>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-cyber-border bg-cyber-bg/50">
              <button onClick={() => { setEditModalOpen(false); setEditingRule(null); }}
                className="px-4 py-2 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-sm hover:text-white transition-all">
                Cancel
              </button>
              <button onClick={handleEditSubmit} disabled={editSubmitting}
                className="flex items-center gap-1.5 px-5 py-2 bg-sentinel-600 text-white rounded-lg text-sm font-medium hover:bg-sentinel-700 disabled:opacity-30 transition-all">
                {editSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                {editingRule.isTracked && !hasRole("admin") ? "Submit for Approval" : "Apply Changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
