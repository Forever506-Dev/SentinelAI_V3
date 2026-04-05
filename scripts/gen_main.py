path = r"F:\SentinelAI\agent\src\main.rs"

content = r'''//! SentinelAI Endpoint Agent
//!
//! Cross-platform security telemetry collector that monitors processes,
//! file system changes, network connections, and system metrics.
//! Reports to the SentinelAI backend for AI-powered threat analysis.
//! Executes remote commands from the panel in real time.

mod collector;
mod config;
mod detection;
mod executor;
mod transport;

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error, warn};

use crate::config::AgentConfig;
use crate::collector::{TelemetryEvent, CollectorManager};
use crate::transport::BackendClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Create event channel (collectors -> transport)
    let (event_tx, mut event_rx) = mpsc::channel::<TelemetryEvent>(1000);

    // Initialize backend client
    let client = Arc::new(BackendClient::new(&config));

    // Register with backend
    match client.register().await {
        Ok(registration) => {
            info!(
                agent_id = %registration.agent_id,
                "Successfully registered with backend"
            );
        }
        Err(e) => {
            warn!(error = %e, "Failed to register with backend, will retry");
        }
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
                        let result = executor::execute_command(&cmd, &pending.command_id);
                        if let Err(e) = heartbeat_client.send_command_result(&result).await {
                            error!(error = %e, "Failed to submit command result");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Heartbeat failed");
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
                        let result = tokio::task::spawn_blocking(move || {
                            executor::execute_command(&cmd_clone, &cmd_id)
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

    // Event processing loop: batch and send telemetry
    let transport_client = Arc::clone(&client);
    let batch_size = config.telemetry_batch_size;
    let telemetry_handle = tokio::spawn(async move {
        let mut batch: Vec<TelemetryEvent> = Vec::with_capacity(batch_size);
        let mut flush_interval = tokio::time::interval(
            tokio::time::Duration::from_secs(10)
        );

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    batch.push(event);
                    if batch.len() >= batch_size {
                        let events = std::mem::take(&mut batch);
                        if let Err(e) = transport_client.send_telemetry(events).await {
                            warn!(error = %e, "Failed to send telemetry batch");
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        let events = std::mem::take(&mut batch);
                        if let Err(e) = transport_client.send_telemetry(events).await {
                            warn!(error = %e, "Failed to flush telemetry batch");
                        }
                    }
                }
            }
        }
    });

    info!("Agent running - press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping agent");

    // Cleanup
    collector_handle.abort();
    heartbeat_handle.abort();
    command_handle.abort();
    telemetry_handle.abort();

    info!("Agent stopped");
    Ok(())
}
'''

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"  OK {path}")
