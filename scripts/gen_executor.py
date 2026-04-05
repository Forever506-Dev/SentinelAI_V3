import os

path = r"F:\SentinelAI\agent\src\executor.rs"

content = r'''//! Command Executor
//!
//! Handles commands received from the SentinelAI backend:
//! shell execution, system scans, process listing, network connections,
//! installed software enumeration, and more.

use std::process::Command;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sysinfo::{System, Disks, Networks, Pid, CpuRefreshKind, MemoryRefreshKind, RefreshKind};
use tracing::{info, warn, error};

use crate::transport::AgentCommand;

/// Result of executing a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: String,
    pub status: String,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Route a command to the appropriate handler.
pub fn execute_command(cmd: &AgentCommand, command_id: &str) -> CommandResult {
    info!(command = %cmd.command, command_id = %command_id, "Executing command");

    match cmd.command.as_str() {
        "shell"              => execute_shell(cmd, command_id),
        "sysinfo"            => execute_sysinfo(command_id),
        "ps"                 => execute_ps(command_id),
        "netstat"            => execute_netstat(command_id),
        "scan"               => execute_full_scan(command_id),
        "scan_ports"         => execute_scan_ports(cmd, command_id),
        "installed_software" => execute_installed_software(command_id),
        "users"              => execute_users(command_id),
        "startup_items"      => execute_startup(command_id),
        "scheduled_tasks"    => execute_scheduled_tasks(command_id),
        other => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Unknown command: {}", other),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// Shell Execution
// =====================================================================

fn execute_shell(cmd: &AgentCommand, command_id: &str) -> CommandResult {
    let shell_cmd = cmd.parameters
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if shell_cmd.is_empty() {
        return CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: "No command specified in parameters.command".into(),
            data: None,
            exit_code: None,
        };
    }

    info!(shell_command = %shell_cmd, "Running shell command");

    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C", shell_cmd]).output()
    } else {
        Command::new("sh").args(["-c", shell_cmd]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout.clone()
            } else if stdout.is_empty() {
                stderr.clone()
            } else {
                format!("{}\n--- stderr ---\n{}", stdout, stderr)
            };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: combined,
                data: Some(json!({
                    "stdout": stdout,
                    "stderr": stderr,
                })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed to execute command: {}", e),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// System Information
// =====================================================================

fn execute_sysinfo(command_id: &str) -> CommandResult {
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );
    sys.refresh_all();

    let disks = Disks::new_with_refreshed_list();
    let networks = Networks::new_with_refreshed_list();

    let disk_info: Vec<serde_json::Value> = disks.list().iter().map(|d| {
        let total = d.total_space();
        let avail = d.available_space();
        json!({
            "mount": d.mount_point().to_string_lossy(),
            "name": d.name().to_string_lossy(),
            "fs": String::from_utf8_lossy(d.file_system().as_encoded_bytes()),
            "total_gb": total as f64 / 1_073_741_824.0,
            "used_gb": (total - avail) as f64 / 1_073_741_824.0,
            "free_gb": avail as f64 / 1_073_741_824.0,
            "usage_pct": if total > 0 { ((total - avail) as f64 / total as f64) * 100.0 } else { 0.0 },
        })
    }).collect();

    let net_info: Vec<serde_json::Value> = networks.iter().map(|(name, data)| {
        json!({
            "interface": name,
            "rx_bytes": data.total_received(),
            "tx_bytes": data.total_transmitted(),
            "rx_packets": data.total_packets_received(),
            "tx_packets": data.total_packets_transmitted(),
        })
    }).collect();

    let per_core: Vec<f32> = sys.cpus().iter().map(|c| c.cpu_usage()).collect();

    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();

    let data = json!({
        "hostname": System::host_name(),
        "os_name": System::name(),
        "os_version": System::os_version(),
        "kernel_version": System::kernel_version(),
        "architecture": std::env::consts::ARCH,
        "uptime_secs": System::uptime(),
        "boot_time": System::boot_time(),
        "cpu": {
            "brand": sys.cpus().first().map(|c| c.brand().to_string()),
            "physical_cores": sys.physical_core_count(),
            "logical_cores": sys.cpus().len(),
            "global_usage_pct": sys.global_cpu_info().cpu_usage(),
            "per_core_pct": per_core,
        },
        "memory": {
            "total_gb": total_mem as f64 / 1_073_741_824.0,
            "used_gb": used_mem as f64 / 1_073_741_824.0,
            "free_gb": sys.free_memory() as f64 / 1_073_741_824.0,
            "usage_pct": if total_mem > 0 { (used_mem as f64 / total_mem as f64) * 100.0 } else { 0.0 },
            "swap_total_gb": sys.total_swap() as f64 / 1_073_741_824.0,
            "swap_used_gb": sys.used_swap() as f64 / 1_073_741_824.0,
        },
        "disks": disk_info,
        "network_interfaces": net_info,
    });

    let mut lines = Vec::new();
    lines.push(format!("Hostname: {}", System::host_name().unwrap_or_default()));
    lines.push(format!("OS: {} {}", System::name().unwrap_or_default(), System::os_version().unwrap_or_default()));
    lines.push(format!("Kernel: {}", System::kernel_version().unwrap_or_default()));
    lines.push(format!("Arch: {}", std::env::consts::ARCH));
    lines.push(format!("Uptime: {}s", System::uptime()));
    lines.push(format!("CPU: {} ({} cores) @ {:.1}%",
        sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
        sys.cpus().len(),
        sys.global_cpu_info().cpu_usage()));
    lines.push(format!("Memory: {:.1}/{:.1} GB ({:.1}%)",
        used_mem as f64 / 1_073_741_824.0,
        total_mem as f64 / 1_073_741_824.0,
        if total_mem > 0 { (used_mem as f64 / total_mem as f64) * 100.0 } else { 0.0 }));
    for d in disks.list() {
        let total = d.total_space();
        let avail = d.available_space();
        lines.push(format!("Disk {}: {:.1}/{:.1} GB",
            d.mount_point().to_string_lossy(),
            (total - avail) as f64 / 1_073_741_824.0,
            total as f64 / 1_073_741_824.0));
    }

    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".into(),
        output: lines.join("\n"),
        data: Some(data),
        exit_code: Some(0),
    }
}

// =====================================================================
// Process Listing
// =====================================================================

fn execute_ps(command_id: &str) -> CommandResult {
    let mut sys = System::new();
    sys.refresh_processes();

    let mut procs: Vec<serde_json::Value> = sys.processes().iter().map(|(pid, p)| {
        json!({
            "pid": pid.as_u32(),
            "name": p.name(),
            "cpu_pct": p.cpu_usage(),
            "memory_mb": p.memory() as f64 / 1_048_576.0,
            "status": format!("{:?}", p.status()),
            "cmd": p.cmd().join(" "),
            "exe": p.exe().map(|e| e.to_string_lossy().to_string()),
            "ppid": p.parent().map(|pp| pp.as_u32()),
            "user": p.user_id().map(|u| format!("{:?}", u)),
            "start_time": p.start_time(),
        })
    }).collect();

    // Sort by CPU usage descending
    procs.sort_by(|a, b| {
        b.get("cpu_pct").and_then(|v| v.as_f64()).unwrap_or(0.0)
            .partial_cmp(&a.get("cpu_pct").and_then(|v| v.as_f64()).unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let count = procs.len();

    // Human-readable top 30
    let mut lines = vec![format!("Total processes: {}", count)];
    lines.push(format!("{:<8} {:<30} {:>6} {:>10} {}", "PID", "NAME", "CPU%", "MEM(MB)", "COMMAND"));
    lines.push("-".repeat(80));
    for p in procs.iter().take(30) {
        lines.push(format!("{:<8} {:<30} {:>5.1}% {:>10.1} {}",
            p["pid"],
            p["name"].as_str().unwrap_or("?"),
            p["cpu_pct"].as_f64().unwrap_or(0.0),
            p["memory_mb"].as_f64().unwrap_or(0.0),
            p["cmd"].as_str().unwrap_or("").chars().take(60).collect::<String>()));
    }
    if count > 30 {
        lines.push(format!("... and {} more processes", count - 30));
    }

    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".into(),
        output: lines.join("\n"),
        data: Some(json!({"processes": procs, "total": count})),
        exit_code: Some(0),
    }
}

// =====================================================================
// Network Connections
// =====================================================================

fn execute_netstat(command_id: &str) -> CommandResult {
    // Use OS command for reliable connection listing
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C", "netstat -ano"]).output()
    } else {
        Command::new("sh").args(["-c", "ss -tunapo 2>/dev/null || netstat -tunapo 2>/dev/null"]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: stdout,
                data: None,
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed: {}", e),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// Full System Scan (combines sysinfo + ps + netstat)
// =====================================================================

fn execute_full_scan(command_id: &str) -> CommandResult {
    let sysinfo = execute_sysinfo(command_id);
    let ps = execute_ps(command_id);
    let netstat = execute_netstat(command_id);
    let software = execute_installed_software(command_id);
    let users = execute_users(command_id);

    let combined_output = format!(
        "=== SYSTEM INFO ===\n{}\n\n=== TOP PROCESSES ===\n{}\n\n=== NETWORK CONNECTIONS ===\n{}\n\n=== INSTALLED SOFTWARE ===\n{}\n\n=== USERS ===\n{}",
        sysinfo.output, ps.output, netstat.output, software.output, users.output
    );

    let combined_data = json!({
        "sysinfo": sysinfo.data,
        "processes": ps.data,
        "network": netstat.data,
        "software": software.data,
        "users": users.data,
    });

    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".into(),
        output: combined_output,
        data: Some(combined_data),
        exit_code: Some(0),
    }
}

// =====================================================================
// Port Scanning
// =====================================================================

fn execute_scan_ports(cmd: &AgentCommand, command_id: &str) -> CommandResult {
    // List listening ports on this machine
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C", "netstat -an | findstr LISTENING"]).output()
    } else {
        Command::new("sh").args(["-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: stdout,
                data: None,
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed: {}", e),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// Installed Software
// =====================================================================

fn execute_installed_software(command_id: &str) -> CommandResult {
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C",
            r#"powershell -NoProfile -Command "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 200""#
        ]).output()
    } else if cfg!(target_os = "macos") {
        Command::new("sh").args(["-c", "system_profiler SPApplicationsDataType 2>/dev/null | head -200"]).output()
    } else {
        Command::new("sh").args(["-c", "dpkg -l 2>/dev/null || rpm -qa --queryformat '%{NAME} %{VERSION}\\n' 2>/dev/null || pacman -Q 2>/dev/null"]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: stdout,
                data: None,
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed: {}", e),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// User Accounts
// =====================================================================

fn execute_users(command_id: &str) -> CommandResult {
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C", "net user"]).output()
    } else {
        Command::new("sh").args(["-c", "cat /etc/passwd | grep -v nologin | grep -v false"]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: stdout,
                data: None,
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed: {}", e),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// Startup Items
// =====================================================================

fn execute_startup(command_id: &str) -> CommandResult {
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C",
            r#"powershell -NoProfile -Command "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String -Width 200""#
        ]).output()
    } else {
        Command::new("sh").args(["-c",
            "systemctl list-unit-files --type=service --state=enabled 2>/dev/null || ls /etc/init.d/ 2>/dev/null"
        ]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: stdout,
                data: None,
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed: {}", e),
            data: None,
            exit_code: None,
        },
    }
}

// =====================================================================
// Scheduled Tasks
// =====================================================================

fn execute_scheduled_tasks(command_id: &str) -> CommandResult {
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C", "schtasks /query /fo CSV /v"]).output()
    } else {
        Command::new("sh").args(["-c",
            "crontab -l 2>/dev/null; echo '---'; for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do echo \"=== $u ===\"; crontab -u $u -l 2>/dev/null; done"
        ]).output()
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            // Truncate if too large
            let truncated = if stdout.len() > 50000 {
                format!("{}...\n\n[Output truncated at 50KB]", &stdout[..50000])
            } else {
                stdout
            };
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: truncated,
                data: None,
                exit_code: output.status.code(),
            }
        }
        Err(e) => CommandResult {
            command_id: command_id.to_string(),
            status: "error".into(),
            output: format!("Failed: {}", e),
            data: None,
            exit_code: None,
        },
    }
}
'''

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"  OK {path}")
