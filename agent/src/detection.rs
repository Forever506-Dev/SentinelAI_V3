//! Local Detection Engine
//!
//! Runs lightweight heuristic rules and pattern matching on telemetry
//! events **before** they leave the endpoint.  High-confidence matches
//! are flagged as alerts; everything else is sent to the backend for
//! deeper AI-powered analysis.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::collector::{EventType, TelemetryEvent};

// ═══════════════════════════════════════════════════════════════════
// Detection Rule Engine
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub mitre_technique: Option<String>,
    pub rule_type: RuleType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// Substring case-insensitive match on process name.
    ProcessName(String),
    /// Exact case-insensitive process name match (with or without .exe suffix).
    /// Avoids false positives from substring matches (e.g. "whoami" won't match
    /// "notamalware_whoami_helper").
    ProcessNameExact(String),
    /// Substring match on the full command line.
    ProcessCommandLine(String),
    /// Regex match on the full command line — use for precise patterns that
    /// need to avoid false positives (e.g. Base64 payload detection).
    ProcessCommandLineRegex(String),
    /// Substring match on file path.
    FilePathPattern(String),
    NetworkPort(u16),
    NetworkDestination(String),
    /// All sub-rules must match (AND logic).
    Combined(Vec<RuleType>),
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub mitre_technique: Option<String>,
    pub event: TelemetryEvent,
    pub context: serde_json::Value,
}

/// The detection engine that evaluates events against a rule set.
pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
}

impl DetectionEngine {
    /// Create the engine pre-loaded with built-in rules.
    pub fn new() -> Self {
        Self {
            rules: builtin_rules(),
        }
    }

    /// Evaluate a single telemetry event against all rules.
    /// Returns a vec of alerts (may be empty).
    pub fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionAlert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if rule_matches(rule, event) {
                warn!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "Detection rule triggered"
                );
                alerts.push(DetectionAlert {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    mitre_technique: rule.mitre_technique.clone(),
                    event: event.clone(),
                    context: json!({
                        "rule_description": rule.description,
                    }),
                });
            }
        }

        alerts
    }

    /// Hot-reload rules (e.g. received from backend).
    pub fn load_rules(&mut self, rules: Vec<DetectionRule>) {
        info!(count = rules.len(), "Loaded detection rules from backend");
        self.rules = rules;
    }

    /// Append additional rules without replacing existing ones.
    pub fn add_rules(&mut self, rules: Vec<DetectionRule>) {
        self.rules.extend(rules);
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Rule matching logic
// ═══════════════════════════════════════════════════════════════════

fn rule_matches(rule: &DetectionRule, event: &TelemetryEvent) -> bool {
    match &rule.rule_type {
        RuleType::ProcessName(name) => {
            if event.event_type != EventType::Process {
                return false;
            }
            event
                .data
                .get("process_name")
                .or_else(|| event.data.get("name"))
                .and_then(|v| v.as_str())
                .map(|n| n.to_lowercase().contains(&name.to_lowercase()))
                .unwrap_or(false)
        }

        RuleType::ProcessNameExact(name) => {
            if event.event_type != EventType::Process {
                return false;
            }
            // Matches exact process name with or without .exe suffix.
            let pattern = format!("(?i)^{}(\\.exe)?$", regex::escape(name));
            let Ok(re) = Regex::new(&pattern) else {
                return false;
            };
            event
                .data
                .get("process_name")
                .or_else(|| event.data.get("name"))
                .and_then(|v| v.as_str())
                .map(|n| re.is_match(n))
                .unwrap_or(false)
        }

        RuleType::ProcessCommandLine(pattern) => {
            if event.event_type != EventType::Process {
                return false;
            }
            event
                .data
                .get("command_line")
                .and_then(|v| v.as_str())
                .map(|cmd| cmd.to_lowercase().contains(&pattern.to_lowercase()))
                .unwrap_or(false)
        }

        RuleType::ProcessCommandLineRegex(pattern) => {
            if event.event_type != EventType::Process {
                return false;
            }
            let Ok(re) = Regex::new(&format!("(?i){}", pattern)) else {
                warn!(pattern = %pattern, "Invalid regex in detection rule — skipping");
                return false;
            };
            event
                .data
                .get("command_line")
                .and_then(|v| v.as_str())
                .map(|cmd| re.is_match(cmd))
                .unwrap_or(false)
        }

        RuleType::FilePathPattern(pattern) => {
            if event.event_type != EventType::File {
                return false;
            }
            event
                .data
                .get("file_path")
                .or_else(|| event.data.get("path"))
                .and_then(|v| v.as_str())
                .map(|p| p.to_lowercase().contains(&pattern.to_lowercase()))
                .unwrap_or(false)
        }

        RuleType::NetworkPort(port) => {
            if event.event_type != EventType::Network {
                return false;
            }
            event
                .data
                .get("dest_port")
                .and_then(|v| v.as_u64())
                .map(|p| p == *port as u64)
                .unwrap_or(false)
        }

        RuleType::NetworkDestination(dest) => {
            if event.event_type != EventType::Network {
                return false;
            }
            event
                .data
                .get("dest_ip")
                .and_then(|v| v.as_str())
                .map(|d| d == dest)
                .unwrap_or(false)
        }

        RuleType::Combined(sub_rules) => {
            sub_rules.iter().all(|sr| {
                let tmp = DetectionRule {
                    id: rule.id.clone(),
                    name: rule.name.clone(),
                    description: String::new(),
                    severity: rule.severity.clone(),
                    mitre_technique: None,
                    rule_type: sr.clone(),
                };
                rule_matches(&tmp, event)
            })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Built-in heuristic rules
// ═══════════════════════════════════════════════════════════════════

fn builtin_rules() -> Vec<DetectionRule> {
    vec![
        // ── Credential Access ───────────────────────────────────
        DetectionRule {
            id: "DETECT-001".into(),
            name: "Mimikatz Detected".into(),
            description: "Process name matches known credential-dumping tool Mimikatz".into(),
            severity: Severity::Critical,
            mitre_technique: Some("T1003".into()),
            rule_type: RuleType::ProcessName("mimikatz".into()),
        },
        // ── Execution: PowerShell Encoded Command ───────────────
        // DETECT-002 keeps the broad substring match as a fast pre-filter.
        // DETECT-014 adds a precise regex check with Base64 payload validation.
        DetectionRule {
            id: "DETECT-002".into(),
            name: "Encoded PowerShell Command".into(),
            description: "PowerShell launched with -EncodedCommand flag, commonly used for obfuscation".into(),
            severity: Severity::High,
            mitre_technique: Some("T1059.001".into()),
            rule_type: RuleType::ProcessCommandLine("-encodedcommand".into()),
        },
        // ── Persistence: Registry Run Key Modification ──────────
        DetectionRule {
            id: "DETECT-003".into(),
            name: "Run Key Modification".into(),
            description: "File written to Windows Run key path — possible persistence".into(),
            severity: Severity::High,
            mitre_technique: Some("T1547.001".into()),
            rule_type: RuleType::FilePathPattern("currentversion\\run".into()),
        },
        // ── Defense Evasion: LOLBIN Execution ───────────────────
        DetectionRule {
            id: "DETECT-004".into(),
            name: "LOLBin: certutil Download".into(),
            description: "certutil.exe invoked with -urlcache, likely downloading payload".into(),
            severity: Severity::High,
            mitre_technique: Some("T1218".into()),
            rule_type: RuleType::ProcessCommandLine("-urlcache".into()),
        },
        DetectionRule {
            id: "DETECT-005".into(),
            name: "LOLBin: mshta.exe Execution".into(),
            description: "mshta.exe process detected — commonly abused for script execution".into(),
            severity: Severity::Medium,
            mitre_technique: Some("T1218.005".into()),
            rule_type: RuleType::ProcessName("mshta".into()),
        },
        // ── Lateral Movement: PsExec ────────────────────────────
        DetectionRule {
            id: "DETECT-006".into(),
            name: "PsExec Detected".into(),
            description: "PsExec process detected — may indicate lateral movement".into(),
            severity: Severity::High,
            mitre_technique: Some("T1570".into()),
            rule_type: RuleType::ProcessName("psexec".into()),
        },
        // ── Impact: Ransomware Indicators ───────────────────────
        DetectionRule {
            id: "DETECT-007".into(),
            name: "Shadow Copy Deletion".into(),
            description: "vssadmin or wmic used to delete shadow copies — ransomware indicator".into(),
            severity: Severity::Critical,
            mitre_technique: Some("T1490".into()),
            rule_type: RuleType::ProcessCommandLine("delete shadows".into()),
        },
        // ── C2: Suspicious Outbound Ports ───────────────────────
        DetectionRule {
            id: "DETECT-008".into(),
            name: "Cobalt Strike Default Port".into(),
            description: "Outbound connection on port 50050 — Cobalt Strike team server default".into(),
            severity: Severity::Critical,
            mitre_technique: Some("T1071.001".into()),
            rule_type: RuleType::NetworkPort(50050),
        },
        DetectionRule {
            id: "DETECT-009".into(),
            name: "Metasploit Default Port".into(),
            description: "Outbound connection on port 4444 — Metasploit default listener".into(),
            severity: Severity::High,
            mitre_technique: Some("T1071.001".into()),
            rule_type: RuleType::NetworkPort(4444),
        },
        // ── Discovery: whoami ───────────────────────────────────
        // Uses ProcessNameExact to avoid false positives on process names
        // that merely contain "whoami" as a substring.
        DetectionRule {
            id: "DETECT-010".into(),
            name: "Reconnaissance: whoami".into(),
            description: "whoami.exe execution — common in initial recon after compromise".into(),
            severity: Severity::Low,
            mitre_technique: Some("T1033".into()),
            rule_type: RuleType::ProcessNameExact("whoami".into()),
        },
        // ── Exfiltration: Rclone ────────────────────────────────
        DetectionRule {
            id: "DETECT-011".into(),
            name: "Data Exfiltration via Rclone".into(),
            description: "rclone process detected — commonly used for data exfiltration to cloud".into(),
            severity: Severity::Critical,
            mitre_technique: Some("T1567".into()),
            rule_type: RuleType::ProcessName("rclone".into()),
        },
        // ── Execution: Windows Script Host ──────────────────────
        // Split into two exact-match rules (wscript / cscript) to avoid
        // matching legitimate processes with those strings in their name.
        DetectionRule {
            id: "DETECT-012".into(),
            name: "Script Host: wscript".into(),
            description: "wscript.exe process detected — Windows Script Host, potential malicious VBS/JS".into(),
            severity: Severity::Medium,
            mitre_technique: Some("T1059.005".into()),
            rule_type: RuleType::ProcessNameExact("wscript".into()),
        },
        DetectionRule {
            id: "DETECT-013".into(),
            name: "Script Host: cscript".into(),
            description: "cscript.exe process detected — Windows Script Host variant".into(),
            severity: Severity::Medium,
            mitre_technique: Some("T1059.005".into()),
            rule_type: RuleType::ProcessNameExact("cscript".into()),
        },
        // ── Execution: Encoded PowerShell (precise regex) ───────
        // Complements DETECT-002 with a stricter regex that requires an
        // actual Base64-looking payload after the flag, reducing noise.
        DetectionRule {
            id: "DETECT-014".into(),
            name: "Encoded PowerShell Command (regex)".into(),
            description: "PowerShell -enc/-en/-EncodedCommand flag followed by Base64 payload".into(),
            severity: Severity::High,
            mitre_technique: Some("T1059.001".into()),
            rule_type: RuleType::ProcessCommandLineRegex(
                r"powershell(\.exe)?\s+.*-(e(nc(odedcommand)?)?|en)\s+[A-Za-z0-9+/=]{20,}".into()
            ),
        },
    ]
}
