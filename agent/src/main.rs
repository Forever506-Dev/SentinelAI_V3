//! SentinelAI Endpoint Agent
//!
//! Cross-platform security telemetry collector that monitors processes,
//! file system changes, network connections, and system metrics.
//! Reports to the SentinelAI backend for AI-powered threat analysis.
//! Executes remote commands from the panel in real time.

mod collector;
mod config;
mod detection;
mod executor;
mod firewall;
mod transport;
#[cfg(windows)]
mod wfp;

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, error, warn};

use crate::config::AgentConfig;
use crate::collector::{TelemetryEvent, CollectorManager};
use crate::detection::DetectionEngine;
use crate::transport::BackendClient;

// ── Windows Service support ──────────────────────────────────────────────────
#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode,
            ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "SentinelAIAgent";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    // Generate the Windows service boilerplate
    define_windows_service!(ffi_service_main, service_main);

    /// Called by the Windows SCM to start our service
    pub fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            // tracing may not be initialized yet, write to a crash log
            let log_dir = std::path::PathBuf::from(r"C:\ProgramData\SentinelAI");
            let _ = std::fs::create_dir_all(&log_dir);
            let _ = std::fs::write(
                log_dir.join("service_crash.log"),
                format!("Service error: {}\n", e),
            );
        }
    }

    fn run_service() -> Result<(), Box<dyn std::error::Error>> {
        // Create a channel to receive stop events from SCM
        let (scm_shutdown_tx, scm_shutdown_rx) = std::sync::mpsc::channel();

        // Register the service control handler
        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control_event| -> ServiceControlHandlerResult {
                match control_event {
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        let _ = scm_shutdown_tx.send(());
                        ServiceControlHandlerResult::NoError
                    }
                    ServiceControl::Interrogate => {
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            },
        )?;

        // Tell SCM we are running
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        // Build a tokio runtime and run the agent inside it
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            // Create a oneshot channel — SCM stop signal bridges into tokio
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

            // Bridge the blocking SCM shutdown channel to the async oneshot
            tokio::spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = scm_shutdown_rx.recv(); // blocks until SCM sends Stop
                }).await;
                let _ = shutdown_tx.send(());
            });

            // Run the agent with the SCM shutdown receiver
            if let Err(e) = super::run_agent(shutdown_rx).await {
                eprintln!("Agent core error: {}", e);
            }
        });

        // Tell SCM we are stopped
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }

    /// Try to start as a Windows Service. Returns Err if not launched by SCM
    /// (e.g. user ran the .exe from a console).
    pub fn start_as_service() -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }
}

fn main() {
    // On Windows: try to run as a Windows Service first.
    // If that fails (because we were launched from a console, not SCM),
    // fall back to running as a normal console application.
    #[cfg(windows)]
    {
        match service::start_as_service() {
            Ok(_) => return,    // ran as service, now exiting
            Err(_) => {
                // Not launched by SCM — run as console application
                eprintln!("[SentinelAI] Not launched by SCM, running as console application...");
            }
        }
    }

    // Console mode (Linux/macOS always, Windows when double-clicked or run from terminal)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    rt.block_on(async {
        // Create a oneshot channel — ctrl+c fires the sender
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => { let _ = shutdown_tx.send(()); }
                Err(e) => eprintln!("ctrl-c handler error: {}", e),
            }
        });

        if let Err(e) = run_agent(shutdown_rx).await {
            eprintln!("Agent error: {}", e);
            std::process::exit(1);
        }
    });
}

/// Core agent logic — receives a shutdown signal from either console Ctrl+C
/// or the Windows SCM stop handler.
async fn run_agent(shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel_agent=info".into()),
        )
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "SentinelAI Agent starting"
    );

    // Load configuration
    let config = AgentConfig::load()?;
    info!(
        backend_url = %config.backend_url,
        heartbeat_interval = config.heartbeat_interval_secs,
        "Configuration loaded"
    );

    // Probe WFP availability (Windows only)
    #[cfg(windows)]
    {
        let wfp_ok = wfp::probe_wfp_availability();
        info!(wfp_available = %wfp_ok, "WFP probe complete");
    }

    // Create event channel (collectors -> transport)
    let (event_tx, mut event_rx) = mpsc::channel::<TelemetryEvent>(1000);

    // Initialize backend client
    let client = Arc::new(BackendClient::new(&config));

    // Register with backend (retry up to 5 times with backoff)
    let mut registered = false;
    for attempt in 1..=5 {
        match client.register().await {
            Ok(registration) => {
                info!(
                    agent_id = %registration.agent_id,
                    "Successfully registered with backend"
                );
                registered = true;
                break;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    attempt = attempt,
                    "Failed to register with backend, retrying in {}s",
                    attempt * 5
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(attempt * 5)).await;
            }
        }
    }
    if !registered {
        error!("Failed to register after 5 attempts — starting in offline mode, heartbeat will retry");
    }

    // Start collectors
    let collector_manager = CollectorManager::new(config.clone(), event_tx);
    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector_manager.start().await {
            error!(error = %e, "Collector manager failed");
        }
    });

    // Start heartbeat loop
    let heartbeat_client = Arc::clone(&client);
    let heartbeat_interval = config.heartbeat_interval_secs;
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(heartbeat_interval)
        );
        loop {
            interval.tick().await;
            match heartbeat_client.send_heartbeat().await {
                Ok(commands) => {
                    // Process any commands received via heartbeat
                    for pending in commands {
                        info!(
                            command_id = %pending.command_id,
                            command = %pending.command,
                            "Received command via heartbeat"
                        );
                        let cmd = crate::transport::AgentCommand {
                            command: pending.command,
                            parameters: pending.parameters,
                        };
                        let hmac = heartbeat_client.hmac_key().await;
                        let result = executor::execute_command(&cmd, &pending.command_id, hmac.as_deref());
                        if let Err(e) = heartbeat_client.send_command_result(&result).await {
                            error!(error = %e, "Failed to submit command result");
                        }
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    warn!(error = %e, "Heartbeat failed");
                    // Re-register if the agent lost its identity or backend rejected it
                    if err_msg.contains("Heartbeat rejected")
                        || err_msg.contains("Agent not registered")
                    {
                        warn!("Agent not registered or rejected — attempting re-registration");
                        match heartbeat_client.register().await {
                            Ok(reg) => info!(agent_id = %reg.agent_id, "Re-registration successful"),
                            Err(re) => error!(error = %re, "Re-registration also failed"),
                        }
                    }
                }
            }
        }
    });

    // Command polling loop (runs every 2 seconds for responsive remote shell)
    let command_client = Arc::clone(&client);
    let command_handle = tokio::spawn(async move {
        // Wait a few seconds for registration to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(2)
        );
        info!("Command polling loop started (every 2s)");
        loop {
            interval.tick().await;
            match command_client.poll_commands().await {
                Ok(commands) => {
                    for pending in commands {
                        info!(
                            command_id = %pending.command_id,
                            command = %pending.command,
                            "Executing remote command"
                        );
                        let cmd = crate::transport::AgentCommand {
                            command: pending.command,
                            parameters: pending.parameters,
                        };
                        // Execute synchronously (blocking) in a spawn_blocking
                        // so we don't block the async runtime for long commands
                        let cmd_clone = cmd.clone();
                        let cmd_id = pending.command_id.clone();
                        let hmac = command_client.hmac_key().await;
                        let result = tokio::task::spawn_blocking(move || {
                            executor::execute_command(&cmd_clone, &cmd_id, hmac.as_deref())
                        }).await.unwrap_or_else(|e| {
                            crate::executor::CommandResult {
                                command_id: pending.command_id.clone(),
                                status: "error".into(),
                                output: format!("Task panicked: {}", e),
                                data: None,
                                exit_code: None,
                            }
                        });
                        info!(
                            command_id = %result.command_id,
                            status = %result.status,
                            output_len = result.output.len(),
                            "Command execution complete"
                        );
                        if let Err(e) = command_client.send_command_result(&result).await {
                            error!(error = %e, "Failed to submit command result");
                        }
                    }
                }
                Err(e) => {
                    // Don't warn on every poll failure (noisy)
                    tracing::trace!(error = %e, "Command poll failed");
                }
            }
        }
    });

    // Event processing loop: detect locally then batch and send telemetry.
    // Failed batches are retried up to MAX_TELEMETRY_RETRIES times with
    // exponential backoff before being dropped.
    let transport_client = Arc::clone(&client);
    let batch_size = config.telemetry_batch_size;
    let telemetry_handle = tokio::spawn(async move {
        let mut batch: Vec<TelemetryEvent> = Vec::with_capacity(batch_size);
        let mut flush_interval = tokio::time::interval(
            tokio::time::Duration::from_secs(10)
        );
        // Pending retry queue: (events, attempt_number)
        let mut retry_queue: Vec<(Vec<TelemetryEvent>, u32)> = Vec::new();
        const MAX_TELEMETRY_RETRIES: u32 = 3;

        // Initialize local detection engine
        let detection = DetectionEngine::new();
        info!(
            rule_count = detection.rule_count(),
            "Local detection engine initialized"
        );

        loop {
            // Drain the retry queue first (oldest failed batches)
            let mut next_retry: Vec<(Vec<TelemetryEvent>, u32)> = Vec::new();
            for (failed_events, attempt) in retry_queue.drain(..) {
                // Exponential backoff: wait 2^attempt seconds (2s, 4s, 8s)
                let backoff = tokio::time::Duration::from_secs(2u64.pow(attempt));
                tokio::time::sleep(backoff).await;
                match transport_client.send_telemetry(failed_events.clone()).await {
                    Ok(_) => info!(attempt, "Telemetry retry succeeded"),
                    Err(e) if attempt < MAX_TELEMETRY_RETRIES => {
                        warn!(
                            error = %e,
                            attempt,
                            "Telemetry retry failed, will retry again"
                        );
                        next_retry.push((failed_events, attempt + 1));
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            events = failed_events.len(),
                            "Telemetry batch dropped after {} retries",
                            MAX_TELEMETRY_RETRIES
                        );
                    }
                }
            }
            retry_queue = next_retry;

            tokio::select! {
                Some(event) = event_rx.recv() => {
                    // ── Local Detection: evaluate event against rules ──
                    let alerts = detection.evaluate(&event);
                    for alert in &alerts {
                        warn!(
                            rule_id = %alert.rule_id,
                            rule_name = %alert.rule_name,
                            severity = ?alert.severity,
                            mitre = ?alert.mitre_technique,
                            "⚠ LOCAL DETECTION: {}", alert.rule_name,
                        );
                    }

                    // Send any local alerts to the backend
                    if !alerts.is_empty() {
                        let alert_json = serde_json::to_value(&alerts).unwrap_or_default();
                        if let Err(e) = transport_client.send_local_alerts(&alert_json).await {
                            warn!(error = %e, "Failed to send local alerts to backend");
                        }
                    }

                    batch.push(event);
                    if batch.len() >= batch_size {
                        let events = std::mem::take(&mut batch);
                        if let Err(e) = transport_client.send_telemetry(events.clone()).await {
                            warn!(error = %e, "Telemetry batch failed, queuing for retry");
                            retry_queue.push((events, 1));
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        let events = std::mem::take(&mut batch);
                        if let Err(e) = transport_client.send_telemetry(events.clone()).await {
                            warn!(error = %e, "Telemetry flush failed, queuing for retry");
                            retry_queue.push((events, 1));
                        }
                    }
                }
            }
        }
    });

    info!("Agent running — waiting for shutdown signal");

    // Wait for shutdown signal (Ctrl+C in console, SCM Stop in service mode)
    let _ = shutdown_rx.await;
    info!("Shutdown signal received, stopping agent");

    // Cleanup
    collector_handle.abort();
    heartbeat_handle.abort();
    command_handle.abort();
    telemetry_handle.abort();

    info!("Agent stopped");
    Ok(())
}
