//! Firewall Management Module
//!
//! Cross-platform firewall rule enumeration and manipulation.
//! Windows: `netsh advfirewall` / `New-NetFirewallRule`
//! Linux:   `ufw` (Uncomplicated Firewall) — primary

use std::process::Command;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::executor::CommandResult;

/// Parsed firewall rule (common representation for both OSes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub direction: String,      // inbound | outbound
    pub action: String,         // allow | block
    pub protocol: String,       // tcp | udp | any | icmp
    pub local_port: String,     // port number(s) or "any"
    pub remote_port: String,
    pub local_address: String,
    pub remote_address: String,
    pub enabled: bool,
    pub profile: String,        // domain | private | public | any
}

// =====================================================================
// List Firewall Rules
// =====================================================================

pub fn list_rules(command_id: &str) -> CommandResult {
    info!("Listing firewall rules");

    if cfg!(windows) {
        list_rules_windows(command_id)
    } else {
        list_rules_linux(command_id)
    }
}

fn list_rules_windows(command_id: &str) -> CommandResult {
    // Use `netsh` for speed — runs in <0.5s vs 25s+ for per-rule PowerShell cmdlets.
    // We fetch inbound + outbound in two fast calls and parse the text blocks.
    let mut all_rules: Vec<serde_json::Value> = Vec::new();

    for dir in ["in", "out"] {
        let result = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all", &format!("dir={}", dir), "status=enabled", "verbose"])
            .output();

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let direction_label = if dir == "in" { "Inbound" } else { "Outbound" };
                parse_netsh_rules(&stdout, direction_label, &mut all_rules);
            }
            Err(e) => {
                info!("netsh {} failed: {}", dir, e);
            }
        }
    }

    // Dedup: Windows Firewall often contains identical duplicate rules
    // (same Name+Direction+Action+Protocol+Port+Address+Profile).
    // Keep only unique rules by hashing all key fields.
    let mut seen = std::collections::HashSet::new();
    all_rules.retain(|r| {
        let key = format!("{}|{}|{}|{}|{}|{}|{}|{}|{}",
            r["Name"].as_str().unwrap_or(""),
            r["Direction"].as_str().unwrap_or(""),
            r["Action"].as_str().unwrap_or(""),
            r["Protocol"].as_str().unwrap_or(""),
            r["LocalPort"].as_str().unwrap_or(""),
            r["RemotePort"].as_str().unwrap_or(""),
            r["LocalAddress"].as_str().unwrap_or(""),
            r["RemoteAddress"].as_str().unwrap_or(""),
            r["Profile"].as_str().unwrap_or(""),
        );
        seen.insert(key)
    });

    let count = all_rules.len();
    let rules_array = json!(all_rules);

    // Human-readable summary
    let mut lines = vec![format!("Active firewall rules: {}", count)];
    lines.push(format!("{:<50} {:>8} {:>7} {:>6} {:>12} {:>15}",
        "NAME", "DIR", "ACTION", "PROTO", "LOCAL PORT", "REMOTE ADDR"));
    lines.push("─".repeat(110));

    for r in all_rules.iter().take(200) {
        lines.push(format!("{:<50} {:>8} {:>7} {:>6} {:>12} {:>15}",
            truncate_str(r["Name"].as_str().unwrap_or("?"), 49),
            r["Direction"].as_str().unwrap_or("?"),
            r["Action"].as_str().unwrap_or("?"),
            r["Protocol"].as_str().unwrap_or("?"),
            r["LocalPort"].as_str().unwrap_or("Any"),
            truncate_str(r["RemoteAddress"].as_str().unwrap_or("Any"), 14),
        ));
    }
    if count > 200 {
        lines.push(format!("... and {} more rules", count - 200));
    }

    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".into(),
        output: lines.join("\n"),
        data: Some(json!({ "rules": rules_array, "total": count, "os": "windows" })),
        exit_code: Some(0),
    }
}

/// Parse `netsh advfirewall firewall show rule ... verbose` text output.
/// Each rule is separated by a blank line, fields are "Key:  Value" lines.
fn parse_netsh_rules(text: &str, default_direction: &str, out: &mut Vec<serde_json::Value>) {
    let mut current: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim();

        // Skip visual separator lines (e.g. "------") — they appear *inside*
        // each rule block right after the Rule Name, NOT between rules.
        if trimmed.starts_with("---") {
            continue;
        }

        // Blank lines and "No rules" markers delimit rule blocks
        if trimmed.is_empty() || trimmed.starts_with("No rules") {
            if !current.is_empty() {
                out.push(netsh_map_to_rule(&current, default_direction));
                current.clear();
            }
            continue;
        }

        // Lines look like: "Rule Name:                       Windows Update"
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().to_string();
            let val = trimmed[pos + 1..].trim().to_string();
            current.insert(key, val);
        }
    }
    // Don't forget last rule
    if !current.is_empty() {
        out.push(netsh_map_to_rule(&current, default_direction));
    }
}

fn netsh_map_to_rule(m: &std::collections::HashMap<String, String>, default_dir: &str) -> serde_json::Value {
    let dir = m.get("Direction").map(|s| s.as_str()).unwrap_or(default_dir);
    let action_raw = m.get("Action").map(|s| s.as_str()).unwrap_or("Allow");
    json!({
        "Name":          m.get("Rule Name").cloned().unwrap_or_default(),
        "Direction":     dir,
        "Action":        action_raw,
        "Protocol":      m.get("Protocol").cloned().unwrap_or_else(|| "Any".into()),
        "LocalPort":     m.get("LocalPort").cloned().unwrap_or_else(|| "Any".into()),
        "RemotePort":    m.get("RemotePort").cloned().unwrap_or_else(|| "Any".into()),
        "LocalAddress":  m.get("LocalIP").cloned().unwrap_or_else(|| "Any".into()),
        "RemoteAddress": m.get("RemoteIP").cloned().unwrap_or_else(|| "Any".into()),
        "Enabled":       m.get("Enabled").cloned().unwrap_or_else(|| "Yes".into()),
        "Profile":       m.get("Profiles").cloned().unwrap_or_else(|| "Any".into()),
    })
}

fn list_rules_linux(command_id: &str) -> CommandResult {
    // Use UFW as the primary firewall management tool on Linux.
    // `ufw status numbered` gives us parseable rule output.
    // Also capture `ufw status verbose` for the human-readable summary.

    // First check if UFW is available and active
    let ufw_check = Command::new("sh")
        .args(["-c", "ufw status 2>/dev/null"])
        .output();

    let ufw_active = match &ufw_check {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            !stdout.contains("inactive") && !stdout.contains("not loaded")
        }
        Err(_) => false,
    };

    if !ufw_active {
        // Try to enable UFW if it's installed but inactive
        let _ = Command::new("sh")
            .args(["-c", "echo 'y' | ufw enable 2>/dev/null"])
            .output();
    }

    // Get verbose status (for human output) and numbered status (for parsing)
    let result = Command::new("sh")
        .args(["-c", r#"
echo "=== UFW STATUS ==="
ufw status verbose 2>/dev/null
echo ""
echo "=== UFW NUMBERED ==="
ufw status numbered 2>/dev/null
echo ""
echo "=== UFW APP LIST ==="
ufw app list 2>/dev/null
"#])
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            // Parse UFW numbered output into structured rules
            let rules = parse_ufw_numbered(&stdout);
            let count = rules.len();

            // Build human-readable summary
            let mut lines = vec![format!("UFW firewall rules: {}", count)];
            lines.push(format!("{:<6} {:<40} {:>8} {:>7} {:>6} {:>12} {:>15}",
                "#", "NAME", "DIR", "ACTION", "PROTO", "PORT", "FROM"));
            lines.push("─".repeat(100));

            for (i, r) in rules.iter().enumerate() {
                lines.push(format!("{:<6} {:<40} {:>8} {:>7} {:>6} {:>12} {:>15}",
                    i + 1,
                    truncate_str(r["Name"].as_str().unwrap_or("—"), 39),
                    r["Direction"].as_str().unwrap_or("—"),
                    r["Action"].as_str().unwrap_or("—"),
                    r["Protocol"].as_str().unwrap_or("any"),
                    r["LocalPort"].as_str().unwrap_or("any"),
                    truncate_str(r["RemoteAddress"].as_str().unwrap_or("Anywhere"), 14),
                ));
            }

            let display = format!("{}\n\n{}", lines.join("\n"), stdout);

            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: display,
                data: Some(json!({ "rules": rules, "total": count, "os": "linux", "firewall": "ufw" })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to list Linux firewall rules: {}", e)),
    }
}

/// Parse `ufw status numbered` output into structured rule objects.
///
/// UFW numbered output looks like:
/// ```text
/// Status: active
///
///      To                         Action      From
///      --                         ------      ----
/// [ 1] 22/tcp                     ALLOW IN    Anywhere
/// [ 2] 80,443/tcp                 ALLOW IN    Anywhere
/// [ 3] Anywhere                   DENY IN     192.168.1.100
/// [ 4] 8080                       DENY OUT    Anywhere                   (out)
/// [ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
/// ```
fn parse_ufw_numbered(raw: &str) -> Vec<serde_json::Value> {
    let mut rules = Vec::new();

    // Find the "=== UFW NUMBERED ===" section
    let numbered_section = if let Some(start) = raw.find("=== UFW NUMBERED ===") {
        &raw[start..]
    } else {
        raw
    };

    for line in numbered_section.lines() {
        let trimmed = line.trim();

        // Match lines like "[ 1] 22/tcp                     ALLOW IN    Anywhere"
        if !trimmed.starts_with('[') {
            continue;
        }

        // Extract the rule number and the rest
        let after_bracket = match trimmed.find(']') {
            Some(pos) => trimmed[pos + 1..].trim(),
            None => continue,
        };

        // Parse the UFW rule line into components
        // Format: <to> <action> <direction> <from> [(comment)]
        if let Some(rule) = parse_ufw_rule_line(after_bracket) {
            rules.push(rule);
        }
    }

    rules
}

/// Parse a single UFW rule line like "22/tcp  ALLOW IN  Anywhere"
/// into a structured JSON object matching the panel's expected format.
fn parse_ufw_rule_line(line: &str) -> Option<serde_json::Value> {
    // Tokenize by splitting on whitespace, but handle multi-word fields
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // The "To" field is first — e.g. "22/tcp", "80,443/tcp", "Anywhere"
    let to_field = parts[0];

    // Find the action keyword (ALLOW, DENY, REJECT, LIMIT)
    let mut action_idx = None;
    for (i, p) in parts.iter().enumerate() {
        let upper = p.to_uppercase();
        if upper == "ALLOW" || upper == "DENY" || upper == "REJECT" || upper == "LIMIT" {
            action_idx = Some(i);
            break;
        }
    }

    let action_idx = action_idx?;
    let action_raw = parts[action_idx].to_uppercase();

    // Direction follows action: "IN" or "OUT" (or absent = IN)
    let (direction, from_start_idx) = if action_idx + 1 < parts.len() {
        let next = parts[action_idx + 1].to_uppercase();
        if next == "IN" {
            ("Inbound".to_string(), action_idx + 2)
        } else if next == "OUT" {
            ("Outbound".to_string(), action_idx + 2)
        } else {
            ("Inbound".to_string(), action_idx + 1) // default inbound
        }
    } else {
        ("Inbound".to_string(), action_idx + 1)
    };

    // "From" field is the rest (e.g. "Anywhere", "192.168.1.100", "Anywhere (v6)")
    let from_field = if from_start_idx < parts.len() {
        parts[from_start_idx..].join(" ")
    } else {
        "Anywhere".to_string()
    };

    // Clean up "(v6)" or "(out)" markers
    let from_clean = from_field
        .replace("(v6)", "")
        .replace("(out)", "")
        .trim()
        .to_string();
    let from_clean = if from_clean.is_empty() { "Anywhere".to_string() } else { from_clean };

    // Skip pure IPv6 duplicate rules (v6) to avoid clutter
    if line.contains("(v6)") {
        return None;
    }

    // Parse the "To" field: "22/tcp" → port=22, proto=tcp
    //                        "80,443/tcp" → port=80,443, proto=tcp
    //                        "Anywhere" → port=any, proto=any
    //                        "3000" → port=3000, proto=any (both)
    let (port, protocol) = parse_ufw_to_field(to_field);

    // Normalize the action for the panel
    let action = match action_raw.as_str() {
        "ALLOW" => "Allow",
        "DENY" => "Block",
        "REJECT" => "Block",
        "LIMIT" => "Limit",
        _ => "Unknown",
    };

    // Build a descriptive name for the rule
    let name = if port == "any" && from_clean == "Anywhere" {
        format!("UFW-{}-{}-all", action, direction)
    } else if port == "any" {
        format!("UFW-{}-{}-from-{}", action, direction, from_clean.replace('.', "_"))
    } else {
        format!("UFW-{}/{}-{}", port, protocol, action.to_lowercase())
    };

    Some(json!({
        "Name":          name,
        "name":          name,
        "Direction":     direction,
        "direction":     direction.to_lowercase(),
        "Action":        action,
        "action":        action.to_lowercase(),
        "Protocol":      protocol,
        "protocol":      protocol,
        "LocalPort":     port,
        "local_port":    port,
        "RemotePort":    "any",
        "remote_port":   "any",
        "LocalAddress":  "any",
        "local_address": "any",
        "RemoteAddress": from_clean,
        "remote_address": from_clean.to_lowercase(),
        "Enabled":       "Yes",
        "enabled":       true,
        "Profile":       "any",
        "profile":       "any",
    }))
}

/// Parse a UFW "To" field like "22/tcp", "80,443/tcp", "3000", "Anywhere"
/// into (port, protocol).
fn parse_ufw_to_field(to_field: &str) -> (String, String) {
    let clean = to_field.replace("(v6)", "").trim().to_string();

    if clean.eq_ignore_ascii_case("anywhere") {
        return ("any".to_string(), "any".to_string());
    }

    if let Some(slash_pos) = clean.find('/') {
        let port = clean[..slash_pos].to_string();
        let proto = clean[slash_pos + 1..].to_lowercase();
        (port, proto)
    } else {
        // Just a port number with no protocol specified → both tcp+udp
        (clean, "any".to_string())
    }
}

// =====================================================================
// Add Firewall Rule
// =====================================================================

pub fn add_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("SentinelAI-Rule");
    let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");
    let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("block");
    let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
    let port = params.get("port").and_then(|v| v.as_str()).unwrap_or("");
    let remote_addr = params.get("remote_address").and_then(|v| v.as_str()).unwrap_or("");

    // Input validation
    if !["inbound", "outbound"].contains(&direction) {
        return error_result(command_id, "Invalid direction: must be 'inbound' or 'outbound'");
    }
    if !["allow", "block"].contains(&action) {
        return error_result(command_id, "Invalid action: must be 'allow' or 'block'");
    }
    if !["tcp", "udp", "any", "icmp"].contains(&protocol) {
        return error_result(command_id, "Invalid protocol: must be 'tcp', 'udp', 'icmp', or 'any'");
    }

    // Validate port if provided
    if !port.is_empty() {
        if let Err(_) = validate_port(port) {
            return error_result(command_id, &format!("Invalid port: {}", port));
        }
    }

    info!(name = %name, direction = %direction, action = %action, protocol = %protocol,
          port = %port, remote_addr = %remote_addr, "Adding firewall rule");

    // Profiles: comma-separated string or JSON array
    let profiles_str: Option<String> = params.get("profiles").and_then(|v| {
        if let Some(s) = v.as_str() {
            if s.is_empty() { None } else { Some(s.to_string()) }
        } else if let Some(arr) = v.as_array() {
            let items: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
            if items.is_empty() { None } else { Some(items.join(",")) }
        } else {
            None
        }
    });

    if cfg!(windows) {
        add_rule_windows(command_id, name, direction, action, protocol, port, remote_addr, profiles_str.as_deref())
    } else {
        add_rule_linux(command_id, direction, action, protocol, port, remote_addr)
    }
}

fn add_rule_windows(command_id: &str, name: &str, direction: &str, action: &str,
                     protocol: &str, port: &str, remote_addr: &str, profiles: Option<&str>) -> CommandResult {
    let dir = if direction == "inbound" { "in" } else { "out" };
    let act = if action == "block" { "block" } else { "allow" };
    let prefixed_name = format!("SentinelAI-{}", name);

    // Delete any existing rule with the same name to prevent OS-level duplicates.
    // `netsh delete rule` removes ALL rules matching the name, which is what we want.
    let del_cmd = format!("netsh advfirewall firewall delete rule name=\"{}\"", prefixed_name);
    let _ = Command::new("cmd").args(["/C", &del_cmd]).output();
    // Ignore errors — rule may not exist yet, which is fine.

    let mut cmd_str = format!(
        "netsh advfirewall firewall add rule name=\"{}\" dir={} action={} protocol={}",
        prefixed_name, dir, act, protocol
    );

    if !port.is_empty() {
        cmd_str.push_str(&format!(" localport={}", port));
    }
    if !remote_addr.is_empty() {
        cmd_str.push_str(&format!(" remoteip={}", remote_addr));
    }
    // Profiles: comma-separated list of domain,private,public
    if let Some(p) = profiles {
        if !p.is_empty() {
            cmd_str.push_str(&format!(" profile={}", p));
        }
    }
    cmd_str.push_str(" enable=yes");

    let result = Command::new("cmd").args(["/C", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout.clone() } else { format!("{}\n{}", stdout, stderr) };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("Rule added: {}\n{}", cmd_str, combined),
                data: Some(json!({
                    "rule_name": prefixed_name,
                    "direction": direction,
                    "action": action,
                    "protocol": protocol,
                    "port": port,
                    "remote_address": remote_addr,
                })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to add rule: {}", e)),
    }
}

fn add_rule_linux(command_id: &str, direction: &str, action: &str,
                   protocol: &str, port: &str, remote_addr: &str) -> CommandResult {
    // Build UFW command:
    //   ufw [allow|deny|reject|limit] [in|out] [proto <protocol>] [from <addr>] [to any port <port>]
    //   ufw allow in proto tcp from 192.168.1.0/24 to any port 22
    //   ufw deny in from 10.0.0.5
    //   ufw allow out proto tcp to any port 443

    let ufw_action = match action {
        "block" => "deny",
        "allow" => "allow",
        "reject" => "reject",
        "limit" => "limit",
        _ => "deny",
    };
    let ufw_dir = if direction == "outbound" { "out" } else { "in" };

    let mut cmd_parts: Vec<String> = vec![
        "ufw".to_string(),
        ufw_action.to_string(),
        ufw_dir.to_string(),
    ];

    // Add protocol if not "any"
    if protocol != "any" && !protocol.is_empty() {
        cmd_parts.push("proto".to_string());
        cmd_parts.push(protocol.to_string());
    }

    // Add source address
    if !remote_addr.is_empty() {
        cmd_parts.push("from".to_string());
        cmd_parts.push(remote_addr.to_string());
    } else {
        cmd_parts.push("from".to_string());
        cmd_parts.push("any".to_string());
    }

    // Add destination port
    if !port.is_empty() {
        cmd_parts.push("to".to_string());
        cmd_parts.push("any".to_string());
        cmd_parts.push("port".to_string());
        cmd_parts.push(port.to_string());
    }

    // Add comment for tracking
    cmd_parts.push("comment".to_string());
    cmd_parts.push("'SentinelAI-managed'".to_string());

    let cmd_str = cmd_parts.join(" ");

    info!(cmd = %cmd_str, "Adding UFW rule");

    let result = Command::new("sh").args(["-c", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout.clone() } else { format!("{}\n{}", stdout, stderr) };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("UFW rule added: {}\n{}", cmd_str, combined),
                data: Some(json!({
                    "firewall": "ufw",
                    "direction": direction,
                    "action": action,
                    "protocol": protocol,
                    "port": port,
                    "remote_address": remote_addr,
                    "command": cmd_str,
                })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to add UFW rule: {}", e)),
    }
}

// =====================================================================
// Delete Firewall Rule
// =====================================================================

pub fn delete_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    info!("Deleting firewall rule");

    if cfg!(windows) {
        delete_rule_windows(command_id, params)
    } else {
        delete_rule_linux(command_id, params)
    }
}

fn delete_rule_windows(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");

    if name.is_empty() {
        return error_result(command_id, "Rule name is required for deletion on Windows");
    }

    // Try the exact name first (handles both pre-existing and SentinelAI-prefixed rules)
    let cmd_str = format!("netsh advfirewall firewall delete rule name=\"{}\"", name);
    let result = Command::new("cmd").args(["/C", &cmd_str]).output();

    match result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: format!("Delete: {}\n{}", cmd_str, stdout),
                data: Some(json!({ "deleted_rule": name })),
                exit_code: output.status.code(),
            }
        }
        _ => {
            // Fallback: try with SentinelAI- prefix (rules created by add_rule have this)
            let prefixed = format!("SentinelAI-{}", name);
            let cmd_str2 = format!("netsh advfirewall firewall delete rule name=\"{}\"", prefixed);
            let result2 = Command::new("cmd").args(["/C", &cmd_str2]).output();

            match result2 {
                Ok(output2) => {
                    let stdout = String::from_utf8_lossy(&output2.stdout).to_string();
                    CommandResult {
                        command_id: command_id.to_string(),
                        status: if output2.status.success() { "completed" } else { "error" }.into(),
                        output: format!("Delete (prefixed): {}\n{}", cmd_str2, stdout),
                        data: Some(json!({ "deleted_rule": prefixed })),
                        exit_code: output2.status.code(),
                    }
                }
                Err(e) => error_result(command_id, &format!("Failed to delete rule '{}' (also tried '{}'): {}", name, prefixed, e)),
            }
        }
    }
}

fn delete_rule_linux(command_id: &str, params: &serde_json::Value) -> CommandResult {
    // UFW supports deletion by rule number (preferred) or by specification.
    //
    // By number:  ufw delete 3
    // By spec:    ufw delete allow in proto tcp from any to any port 22

    let rule_number = params.get("rule_number").and_then(|v| v.as_u64());

    let cmd_str = if let Some(num) = rule_number {
        // Delete by rule number (most reliable)
        format!("echo 'y' | ufw delete {}", num)
    } else {
        // Reconstruct the UFW rule specification for deletion
        let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");
        let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("deny");
        let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("any");
        let port = params.get("port").and_then(|v| v.as_str()).unwrap_or("");
        let remote = params.get("remote_address").and_then(|v| v.as_str()).unwrap_or("");

        let ufw_action = match action {
            "block" | "deny" | "DROP" => "deny",
            "allow" | "ACCEPT" => "allow",
            "reject" | "REJECT" => "reject",
            "limit" => "limit",
            _ => "deny",
        };
        let ufw_dir = if direction == "outbound" { "out" } else { "in" };

        let mut parts = vec![
            "echo 'y' | ufw delete".to_string(),
            ufw_action.to_string(),
            ufw_dir.to_string(),
        ];

        if protocol != "any" && !protocol.is_empty() {
            parts.push(format!("proto {}", protocol));
        }

        if !remote.is_empty() {
            parts.push(format!("from {}", remote));
        } else {
            parts.push("from any".to_string());
        }

        if !port.is_empty() {
            parts.push(format!("to any port {}", port));
        }

        parts.join(" ")
    };

    info!(cmd = %cmd_str, "Deleting UFW rule");

    let result = Command::new("sh").args(["-c", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("UFW delete: {}\n{}", cmd_str, combined),
                data: Some(json!({ "command": cmd_str, "firewall": "ufw" })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to delete UFW rule: {}", e)),
    }
}

// =====================================================================
// Edit Firewall Rule (delete + re-add with new params)
// =====================================================================

pub fn edit_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return error_result(command_id, "Rule name is required for edit");
    }

    info!(name = %name, "Editing firewall rule");

    if cfg!(windows) {
        edit_rule_windows(command_id, name, params)
    } else {
        edit_rule_linux(command_id, name, params)
    }
}

/// Edit rule in-place on Windows using `netsh advfirewall firewall set rule`.
/// This modifies the existing rule without changing its name.
/// Note: direction cannot be changed in-place on Windows — it's a selector, not modifiable.
/// If direction changes, we must delete + re-add.
fn edit_rule_windows(command_id: &str, name: &str, params: &serde_json::Value) -> CommandResult {
    let new_direction = params.get("direction").and_then(|v| v.as_str());
    let new_action    = params.get("action").and_then(|v| v.as_str());
    let new_protocol  = params.get("protocol").and_then(|v| v.as_str());
    let new_port      = params.get("port").and_then(|v| v.as_str());
    let new_remote    = params.get("remote_address").and_then(|v| v.as_str());
    // Profiles: either a comma-separated string or a JSON array of strings
    let new_profiles: Option<String> = params.get("profiles").and_then(|v| {
        if let Some(s) = v.as_str() {
            if s.is_empty() { None } else { Some(s.to_string()) }
        } else if let Some(arr) = v.as_array() {
            let items: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
            if items.is_empty() { None } else { Some(items.join(",")) }
        } else {
            None
        }
    });

    // Resolve which actual name exists in Windows Firewall
    let actual_name = resolve_rule_name_windows(name);
    if actual_name.is_none() {
        return error_result(command_id, &format!(
            "Rule '{}' not found in Windows Firewall (also tried 'SentinelAI-{}')", name, name
        ));
    }
    let actual_name = actual_name.unwrap();

    // Build the "new" clause for netsh set rule.
    // Syntax: netsh advfirewall firewall set rule name="X" [dir=in|out] new <field>=<value> ...
    // dir= is a SELECTOR (identifies which rules), not a modifiable field.
    let mut new_parts: Vec<String> = Vec::new();

    if let Some(act) = new_action {
        let a = if act == "block" { "block" } else { "allow" };
        new_parts.push(format!("action={}", a));
    }
    // Determine effective protocol: either the one being set, or the existing one on the rule
    let effective_protocol = new_protocol
        .map(|s| s.to_lowercase())
        .or_else(|| detect_rule_protocol(&actual_name).map(|s| s.to_lowercase()));
    let proto_is_any = effective_protocol.as_deref() == Some("any") || effective_protocol.is_none();

    if let Some(proto) = new_protocol {
        // Only include protocol= if it's not "any" ("any" is the default)
        if !proto.eq_ignore_ascii_case("any") {
            new_parts.push(format!("protocol={}", proto));
        }
    }
    // netsh rejects localport= when protocol is Any — only include for TCP/UDP
    if let Some(p) = new_port {
        if !proto_is_any {
            if !p.is_empty() && !p.eq_ignore_ascii_case("any") {
                new_parts.push(format!("localport={}", p));
            }
        }
    }
    // Only include remoteip= if it's not the default "any"
    if let Some(ra) = new_remote {
        if !ra.is_empty() && !ra.eq_ignore_ascii_case("any") {
            new_parts.push(format!("remoteip={}", ra));
        }
    }
    // Profiles: comma-separated list (domain,private,public)
    if let Some(ref prof) = new_profiles {
        new_parts.push(format!("profile={}", prof));
    }

    // If direction changes, we must delete and re-add since dir is a selector, not settable
    if let Some(dir) = new_direction {
        let old_dir = detect_rule_direction(&actual_name);
        let normalized_new = if dir == "inbound" { "in" } else { "out" };
        if old_dir.as_deref() != Some(normalized_new) {
            info!(name = %actual_name, old_dir = ?old_dir, new_dir = %dir, "Direction change requires delete+re-add");
            // Delete existing rule
            let del_cmd = format!("netsh advfirewall firewall delete rule name=\"{}\"", actual_name);
            let del_result = Command::new("cmd").args(["/C", &del_cmd]).output();
            match del_result {
                Ok(output) if !output.status.success() => {
                    let stderr = String::from_utf8_lossy(&output.stdout);
                    return error_result(command_id, &format!("Failed to delete rule for direction change: {}", stderr));
                }
                Err(e) => return error_result(command_id, &format!("Failed to run delete: {}", e)),
                _ => {}
            }

            // Re-add with new direction and all specified fields, preserving original name
            let dir_flag = if dir == "inbound" { "in" } else { "out" };
            let act = new_action.unwrap_or("allow");
            let act_flag = if act == "block" { "block" } else { "allow" };
            let proto = new_protocol.unwrap_or("any");

            let mut cmd_str = format!(
                "netsh advfirewall firewall add rule name=\"{}\" dir={} action={} protocol={}",
                actual_name, dir_flag, act_flag, proto
            );
            // Only add port if protocol supports it (TCP/UDP)
            let proto_lower = proto.to_lowercase();
            if proto_lower != "any" {
                if let Some(p) = new_port {
                    if !p.is_empty() && !p.eq_ignore_ascii_case("any") {
                        cmd_str.push_str(&format!(" localport={}", p));
                    }
                }
            }
            if let Some(ra) = new_remote {
                if !ra.is_empty() && !ra.eq_ignore_ascii_case("any") {
                    cmd_str.push_str(&format!(" remoteip={}", ra));
                }
            }
            if let Some(ref prof) = new_profiles {
                cmd_str.push_str(&format!(" profile={}", prof));
            }
            cmd_str.push_str(" enable=yes");

            let result = Command::new("cmd").args(["/C", &cmd_str]).output();
            return match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    CommandResult {
                        command_id: command_id.to_string(),
                        status: if output.status.success() { "completed" } else { "error" }.into(),
                        output: format!("Direction changed (delete+re-add): {}\n{}", cmd_str, stdout),
                        data: Some(json!({ "rule_name": actual_name, "direction_changed": true })),
                        exit_code: output.status.code(),
                    }
                }
                Err(e) => error_result(command_id, &format!("Failed to re-add rule: {}", e)),
            };
        }
    }

    if new_parts.is_empty() {
        return error_result(command_id, "No fields to modify");
    }

    // Use `set rule` for in-place modification (direction unchanged)
    // Add dir= as selector to be more precise
    let dir_selector = if let Some(d) = detect_rule_direction(&actual_name) {
        format!(" dir={}", d)
    } else {
        String::new()
    };

    let cmd_str = format!(
        "netsh advfirewall firewall set rule name=\"{}\"{} new {}",
        actual_name, dir_selector, new_parts.join(" ")
    );

    info!(cmd = %cmd_str, "Attempting rule edit");
    let result = Command::new("cmd").args(["/C", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("Rule modified: {}\n{}", cmd_str, combined),
                data: Some(json!({ "rule_name": actual_name, "changes": new_parts })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to modify rule: {}", e)),
    }
}

/// Edit a firewall rule on Linux using UFW.
/// UFW doesn't support in-place edits, so we delete the old rule and re-add with new params.
/// We find the rule by number (preferred) or by matching the rule specification.
fn edit_rule_linux(command_id: &str, name: &str, params: &serde_json::Value) -> CommandResult {
    info!(name = %name, "Editing UFW rule (delete + re-add)");

    // Try to find the rule number by matching name in the UFW numbered list
    if let Some(rule_num) = find_ufw_rule_number(name) {
        let del_cmd = format!("echo 'y' | ufw delete {}", rule_num);
        info!(cmd = %del_cmd, "Deleting old UFW rule by number");
        let _ = Command::new("sh").args(["-c", &del_cmd]).output();
    } else if let Some(num) = params.get("rule_number").and_then(|v| v.as_u64()) {
        let del_cmd = format!("echo 'y' | ufw delete {}", num);
        let _ = Command::new("sh").args(["-c", &del_cmd]).output();
    }
    // If we couldn't find/delete the old rule, we still add the new one

    // Re-add with updated parameters
    add_rule(command_id, params)
}

/// Search `ufw status numbered` output to find the rule number matching a given name/port.
fn find_ufw_rule_number(name: &str) -> Option<u64> {
    let output = Command::new("sh")
        .args(["-c", "ufw status numbered 2>/dev/null"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract port from name patterns like "UFW-22/tcp-allow" or "Block-Port-tcp-443"
    let search_terms: Vec<&str> = name.split(&['-', '/', '_'][..]).collect();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('[') {
            continue;
        }

        // Check if any search term matches this line
        let line_lower = trimmed.to_lowercase();
        let name_lower = name.to_lowercase();

        // Try exact-ish matching: if the name contains a port, look for that port in the line
        let matches = search_terms.iter().any(|term| {
            let t = term.to_lowercase();
            // Only match meaningful terms (ports, ips, not generic words)
            t.parse::<u16>().is_ok() && line_lower.contains(&t)
        }) || line_lower.contains(&name_lower);

        if matches {
            // Extract the number from "[ 3]"
            if let Some(start) = trimmed.find('[') {
                if let Some(end) = trimmed.find(']') {
                    let num_str = trimmed[start + 1..end].trim();
                    return num_str.parse::<u64>().ok();
                }
            }
        }
    }

    None
}

/// Check if a rule name exists in Windows Firewall, trying exact name then SentinelAI- prefix.
fn resolve_rule_name_windows(name: &str) -> Option<String> {
    // Try exact name first
    let cmd = format!("netsh advfirewall firewall show rule name=\"{}\"", name);
    if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("No rules match") && output.status.success() {
            return Some(name.to_string());
        }
    }

    // Try SentinelAI- prefix
    if !name.starts_with("SentinelAI-") {
        let prefixed = format!("SentinelAI-{}", name);
        let cmd = format!("netsh advfirewall firewall show rule name=\"{}\"", prefixed);
        if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains("No rules match") && output.status.success() {
                return Some(prefixed);
            }
        }
    }

    None
}

/// Detect the direction of an existing rule (returns "in" or "out").
fn detect_rule_direction(name: &str) -> Option<String> {
    let cmd = format!("netsh advfirewall firewall show rule name=\"{}\" verbose", name);
    if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(pos) = trimmed.find(':') {
                let key = trimmed[..pos].trim();
                let val = trimmed[pos + 1..].trim();
                if key == "Direction" {
                    return match val {
                        "In" => Some("in".to_string()),
                        "Out" => Some("out".to_string()),
                        _ => None,
                    };
                }
            }
        }
    }
    None
}

/// Detect the protocol of an existing rule (returns e.g. "TCP", "UDP", "Any").
fn detect_rule_protocol(name: &str) -> Option<String> {
    let cmd = format!("netsh advfirewall firewall show rule name=\"{}\" verbose", name);
    if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(pos) = trimmed.find(':') {
                let key = trimmed[..pos].trim();
                let val = trimmed[pos + 1..].trim();
                if key == "Protocol" {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// =====================================================================
// Toggle Firewall Rule (enable/disable)
// =====================================================================

pub fn toggle_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

    if name.is_empty() {
        return error_result(command_id, "Rule name is required for toggle");
    }

    info!(name = %name, enabled = %enabled, "Toggling firewall rule");

    if cfg!(windows) {
        let enable_str = if enabled { "yes" } else { "no" };
        let cmd_str = format!(
            "netsh advfirewall firewall set rule name=\"{}\" new enable={}",
            name, enable_str
        );
        let result = Command::new("cmd").args(["/C", &cmd_str]).output();

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                CommandResult {
                    command_id: command_id.to_string(),
                    status: if output.status.success() { "completed" } else { "error" }.into(),
                    output: format!("Toggle: {}\n{}", cmd_str, stdout),
                    data: Some(json!({ "rule_name": name, "enabled": enabled })),
                    exit_code: output.status.code(),
                }
            }
            Err(e) => error_result(command_id, &format!("Failed to toggle rule: {}", e)),
        }
    } else {
        toggle_rule_linux(command_id, name, enabled)
    }
}

/// Toggle a firewall rule on Linux using UFW.
///
/// UFW has no native enable/disable toggle per-rule. We implement this by:
/// - **Disable**: Delete the matching rule and save its UFW specification to a state file
///   (`/var/lib/sentinelai/disabled_rules.json`) so it can be restored.
/// - **Enable**: Read the saved specification from the state file and re-add it.
fn toggle_rule_linux(command_id: &str, name: &str, enabled: bool) -> CommandResult {
    let state_path = "/var/lib/sentinelai/disabled_rules.json";

    // Load existing disabled rules state
    let mut disabled: std::collections::HashMap<String, String> = std::fs::read_to_string(state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if enabled {
        // Re-enable: restore the saved UFW rule specification
        if let Some(ufw_cmd) = disabled.remove(name) {
            info!(name = %name, cmd = %ufw_cmd, "Re-enabling UFW rule");
            let result = Command::new("sh").args(["-c", &ufw_cmd]).output();

            // Persist updated state
            let _ = std::fs::create_dir_all("/var/lib/sentinelai");
            let _ = std::fs::write(state_path, serde_json::to_string_pretty(&disabled).unwrap_or_default());

            match result {
                Ok(output) if output.status.success() => {
                    CommandResult {
                        command_id: command_id.to_string(),
                        status: "completed".into(),
                        output: format!("Rule '{}' re-enabled via UFW: {}", name, ufw_cmd),
                        data: Some(json!({ "rule_name": name, "enabled": true, "firewall": "ufw" })),
                        exit_code: output.status.code(),
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    error_result(command_id, &format!("Failed to re-enable rule '{}': {}", name, stderr))
                }
                Err(e) => error_result(command_id, &format!("Failed to run UFW: {}", e)),
            }
        } else {
            error_result(command_id, &format!("Rule '{}' not found in disabled rules state", name))
        }
    } else {
        // Disable: find the rule in UFW, save its spec for re-enable, then delete it
        // First, try to reconstruct the UFW add command from the current rules
        if let Some(rule_num) = find_ufw_rule_number(name) {
            // Get the rule specification before deleting
            let ufw_spec = reconstruct_ufw_add_command(name);

            // Delete by number
            let del_cmd = format!("echo 'y' | ufw delete {}", rule_num);
            info!(cmd = %del_cmd, "Disabling UFW rule by number");
            let del_result = Command::new("sh").args(["-c", &del_cmd]).output();

            match del_result {
                Ok(output) if output.status.success() => {
                    // Save the UFW add-command for re-enabling later
                    if let Some(spec) = ufw_spec {
                        disabled.insert(name.to_string(), spec);
                    }
                    let _ = std::fs::create_dir_all("/var/lib/sentinelai");
                    let _ = std::fs::write(state_path, serde_json::to_string_pretty(&disabled).unwrap_or_default());

                    CommandResult {
                        command_id: command_id.to_string(),
                        status: "completed".into(),
                        output: format!("Rule '{}' disabled (removed from UFW, saved for re-enable)", name),
                        data: Some(json!({ "rule_name": name, "enabled": false, "firewall": "ufw" })),
                        exit_code: Some(0),
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    error_result(command_id, &format!("Failed to disable rule: {}", stderr))
                }
                Err(e) => error_result(command_id, &format!("Failed to delete UFW rule: {}", e)),
            }
        } else {
            error_result(command_id, &format!(
                "Could not locate rule '{}' in UFW numbered list", name))
        }
    }
}

/// Try to reconstruct a `ufw allow/deny ...` command from the named rule's parsed data.
/// This is used by toggle to save the rule specification for later re-enabling.
fn reconstruct_ufw_add_command(name: &str) -> Option<String> {
    // Parse the name to extract rule parameters
    // Names look like: "UFW-22/tcp-allow", "UFW-Block-Inbound-from-192_168_1_100"
    // Or from block_ip/block_port: "Block-192-168-1-5", "Block-Port-tcp-443"

    let output = Command::new("sh")
        .args(["-c", "ufw status numbered 2>/dev/null"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let search_terms: Vec<&str> = name.split(&['-', '/', '_'][..]).collect();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('[') {
            continue;
        }

        let line_lower = trimmed.to_lowercase();
        let name_lower = name.to_lowercase();

        let matches = search_terms.iter().any(|term| {
            let t = term.to_lowercase();
            t.parse::<u16>().is_ok() && line_lower.contains(&t)
        }) || line_lower.contains(&name_lower);

        if matches {
            // Parse this line to reconstruct the ufw add command
            if let Some(bracket_end) = trimmed.find(']') {
                let rule_text = trimmed[bracket_end + 1..].trim();
                return Some(reconstruct_from_ufw_line(rule_text));
            }
        }
    }

    None
}

/// Given a UFW status line like "22/tcp  ALLOW IN  Anywhere", reconstruct a `ufw add` command.
fn reconstruct_from_ufw_line(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return format!("ufw allow {}", line);
    }

    let to_field = parts[0];
    let mut action = "allow";
    let mut direction = "in";
    let mut from = "any";

    for (i, p) in parts.iter().enumerate() {
        let upper = p.to_uppercase();
        match upper.as_str() {
            "ALLOW" => action = "allow",
            "DENY" => action = "deny",
            "REJECT" => action = "reject",
            "LIMIT" => action = "limit",
            "IN" => direction = "in",
            "OUT" => direction = "out",
            _ => {
                // Check if it's the from address (after "IN"/"OUT")
                if i >= 3 && !p.starts_with('(') {
                    from = p;
                }
            }
        }
    }

    let (port, proto) = parse_ufw_to_field(to_field);

    let mut cmd = format!("ufw {} {}", action, direction);
    if proto != "any" {
        cmd.push_str(&format!(" proto {}", proto));
    }
    if from != "any" && !from.eq_ignore_ascii_case("anywhere") {
        cmd.push_str(&format!(" from {}", from));
    } else {
        cmd.push_str(" from any");
    }
    if port != "any" {
        cmd.push_str(&format!(" to any port {}", port));
    }

    cmd
}

/// Remove all UFW rules whose status line contains the given comment tag.
/// Iterates from highest rule number downward to avoid index shifting.
fn remove_ufw_rules_by_comment(comment: &str) {
    let out = Command::new("ufw").args(["status", "numbered"]).output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        // Collect (number, _line) pairs for matching rules
        let mut nums: Vec<u32> = Vec::new();
        for line in text.lines() {
            if !line.contains(comment) {
                continue;
            }
            // e.g. "[ 3] Anywhere  DENY IN  Anywhere  (SentinelAI-Quarantine)"
            if let Some(start) = line.find('[') {
                if let Some(end) = line.find(']') {
                    if let Ok(n) = line[start + 1..end].trim().parse::<u32>() {
                        nums.push(n);
                    }
                }
            }
        }
        // Delete from highest number first to keep indices stable
        nums.sort_unstable();
        nums.reverse();
        for n in nums {
            let _ = Command::new("sh")
                .args(["-c", &format!("echo 'y' | ufw delete {}", n)])
                .output();
        }
    }
}

// =====================================================================
// Snapshot Rules (full capture for drift detection)
// =====================================================================

pub fn snapshot_rules(command_id: &str) -> CommandResult {
    info!("Taking full firewall rule snapshot for drift detection");

    // Re-use list_rules but tag it as a snapshot
    let mut result = list_rules(command_id);
    if let Some(ref mut data) = result.data {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("snapshot".into(), json!(true));
            obj.insert("captured_at".into(), json!(chrono::Utc::now().to_rfc3339()));
        }
    }
    result
}

// =====================================================================
// Quarantine (network isolation levels)
// =====================================================================

pub fn set_quarantine(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let level = params.get("level").and_then(|v| v.as_str()).unwrap_or("none");

    info!(level = %level, "Setting quarantine level");

    match level {
        "none" => remove_quarantine(command_id),
        "partial" => apply_partial_quarantine(command_id, params),
        "full" => apply_full_quarantine(command_id, params),
        _ => error_result(command_id, &format!("Unknown quarantine level: {}", level)),
    }
}

fn remove_quarantine(command_id: &str) -> CommandResult {
    info!("Removing quarantine — restoring normal connectivity");

    if cfg!(windows) {
        // Delete all SentinelAI-Quarantine rules
        let cmd = "netsh advfirewall firewall delete rule name=all dir=in | findstr /i \"SentinelAI-Quarantine\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-BlockAll-In\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-BlockAll-Out\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-AllowBackend-In\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-AllowBackend-Out\"";
        let _ = Command::new("cmd").args(["/C", cmd]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "Quarantine removed — normal connectivity restored".into(),
            data: Some(json!({ "quarantine_level": "none" })),
            exit_code: Some(0),
        }
    } else {
        // Remove UFW quarantine rules
        // Delete all SentinelAI-Quarantine deny rules by finding their numbers
        let cmds = vec![
            "echo 'y' | ufw delete deny in comment 'SentinelAI-Quarantine' 2>/dev/null",
            "echo 'y' | ufw delete deny out comment 'SentinelAI-Quarantine' 2>/dev/null",
        ];
        for cmd in &cmds {
            let _ = Command::new("sh").args(["-c", cmd]).output();
        }

        // Also clean up by searching numbered list for quarantine rules
        remove_ufw_rules_by_comment("SentinelAI-Quarantine");

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "Quarantine removed via UFW".into(),
            data: Some(json!({ "quarantine_level": "none", "firewall": "ufw" })),
            exit_code: Some(0),
        }
    }
}

fn apply_partial_quarantine(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let backend_ip = params.get("backend_ip").and_then(|v| v.as_str()).unwrap_or("");

    info!(backend_ip = %backend_ip, "Applying partial quarantine — backend comms only");

    if cfg!(windows) {
        // Step 1: Allow backend communication
        if !backend_ip.is_empty() {
            let allow_in = format!(
                "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-AllowBackend-In\" dir=in action=allow remoteip={} enable=yes",
                backend_ip
            );
            let allow_out = format!(
                "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-AllowBackend-Out\" dir=out action=allow remoteip={} enable=yes",
                backend_ip
            );
            let _ = Command::new("cmd").args(["/C", &allow_in]).output();
            let _ = Command::new("cmd").args(["/C", &allow_out]).output();
        }

        // Step 2: Block everything else
        let block_in = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-In\" dir=in action=block enable=yes";
        let block_out = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-Out\" dir=out action=block enable=yes";
        let _ = Command::new("cmd").args(["/C", block_in]).output();
        let _ = Command::new("cmd").args(["/C", block_out]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: format!("Partial quarantine applied — only backend ({}) allowed", backend_ip),
            data: Some(json!({ "quarantine_level": "partial", "backend_ip": backend_ip })),
            exit_code: Some(0),
        }
    } else {
        // Linux: Use UFW — allow backend, then set default deny
        let mut cmds: Vec<String> = Vec::new();
        if !backend_ip.is_empty() {
            cmds.push(format!("ufw allow in from {} comment 'SentinelAI-Quarantine'", backend_ip));
            cmds.push(format!("ufw allow out to {} comment 'SentinelAI-Quarantine'", backend_ip));
        }
        // Insert deny-all rules at the end
        cmds.push("ufw deny in from any comment 'SentinelAI-Quarantine'".into());
        cmds.push("ufw deny out to any comment 'SentinelAI-Quarantine'".into());

        for cmd in &cmds {
            let _ = Command::new("sh").args(["-c", cmd]).output();
        }

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: format!("Partial quarantine applied via UFW"),
            data: Some(json!({ "quarantine_level": "partial", "backend_ip": backend_ip, "firewall": "ufw" })),
            exit_code: Some(0),
        }
    }
}

fn apply_full_quarantine(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let backend_ip = params.get("backend_ip").and_then(|v| v.as_str()).unwrap_or("");

    info!("Applying FULL quarantine — heartbeat only");

    if cfg!(windows) {
        // Allow only heartbeat port to backend
        if !backend_ip.is_empty() {
            let allow_hb = format!(
                "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-AllowBackend-Out\" dir=out action=allow protocol=tcp remoteip={} remoteport=8000 enable=yes",
                backend_ip
            );
            let _ = Command::new("cmd").args(["/C", &allow_hb]).output();
        }

        // Block all
        let block_in = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-In\" dir=in action=block enable=yes";
        let block_out = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-Out\" dir=out action=block enable=yes";
        let _ = Command::new("cmd").args(["/C", block_in]).output();
        let _ = Command::new("cmd").args(["/C", block_out]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "FULL quarantine — only heartbeat allowed".into(),
            data: Some(json!({ "quarantine_level": "full", "backend_ip": backend_ip })),
            exit_code: Some(0),
        }
    } else {
        // Linux: Use UFW — only allow heartbeat to backend on port 8000
        let mut cmds: Vec<String> = Vec::new();
        if !backend_ip.is_empty() {
            cmds.push(format!("ufw allow out proto tcp to {} port 8000 comment 'SentinelAI-Quarantine'", backend_ip));
        }
        // Block everything else
        cmds.push("ufw deny in from any comment 'SentinelAI-Quarantine'".into());
        cmds.push("ufw deny out to any comment 'SentinelAI-Quarantine'".into());

        for cmd in &cmds {
            let _ = Command::new("sh").args(["-c", cmd]).output();
        }

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "FULL quarantine applied via UFW".into(),
            data: Some(json!({ "quarantine_level": "full", "firewall": "ufw" })),
            exit_code: Some(0),
        }
    }
}

// =====================================================================
// Quick Actions: Block IP / Block Port
// =====================================================================

pub fn block_ip(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let ip = params.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");

    if ip.is_empty() {
        return error_result(command_id, "IP address is required");
    }

    info!(ip = %ip, direction = %direction, "Blocking IP address");

    let rule_params = json!({
        "name": format!("Block-{}", ip.replace('.', "-").replace(':', "-")),
        "direction": direction,
        "action": "block",
        "protocol": "any",
        "port": "",
        "remote_address": ip,
    });

    add_rule(command_id, &rule_params)
}

pub fn block_port(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let port = params.get("port").and_then(|v| v.as_str()).unwrap_or("");
    let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
    let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");

    if port.is_empty() {
        return error_result(command_id, "Port number is required");
    }

    info!(port = %port, protocol = %protocol, direction = %direction, "Blocking port");

    let rule_params = json!({
        "name": format!("Block-Port-{}-{}", protocol, port),
        "direction": direction,
        "action": "block",
        "protocol": protocol,
        "port": port,
        "remote_address": "",
    });

    add_rule(command_id, &rule_params)
}

// =====================================================================
// Helpers
// =====================================================================

fn validate_port(port: &str) -> Result<(), String> {
    // Accept single port or comma-separated or range
    for part in port.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.splitn(2, '-').collect();
            if range.len() != 2 {
                return Err(format!("Invalid range: {}", part));
            }
            range[0].parse::<u16>().map_err(|_| format!("Invalid port: {}", range[0]))?;
            range[1].parse::<u16>().map_err(|_| format!("Invalid port: {}", range[1]))?;
        } else {
            part.parse::<u16>().map_err(|_| format!("Invalid port: {}", part))?;
        }
    }
    Ok(())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Find the nearest char boundary at or before max-1 bytes
        // to avoid panicking on multi-byte UTF-8 (e.g. French « » \u{a0})
        let mut end = max.saturating_sub(1);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

fn error_result(command_id: &str, msg: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "error".into(),
        output: msg.to_string(),
        data: None,
        exit_code: None,
    }
}
