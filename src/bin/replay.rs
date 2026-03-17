//! nix-wire-replay: Replay recorded Nix daemon sessions.
//!
//! Reads a recording, connects to the daemon, sends ClientToDaemon records
//! and reads DaemonToClient responses using protocol-aware parsing.
//!
//! Two modes:
//! - Socket mode (default): connect to the daemon Unix socket
//! - Command mode: spawn a child process (e.g., `nix-daemon --stdio`)

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{error, info, warn};

use nix_wire::handshake::ProtocolVersion;
use nix_wire::ops::Op;
use nix_wire::protocol;
use nix_wire::recording::{Direction, Record, RecordingReader};
use nix_wire::stderr::StderrCode;
use nix_wire::wire_async::{AsyncWireReader, MemReader};

#[derive(Parser)]
#[command(
    name = "nix-wire-replay",
    about = "Replay recorded Nix daemon wire protocol sessions"
)]
struct Args {
    /// Path to the .nixwire recording file
    #[arg(long)]
    recording: PathBuf,

    /// Nix store root (derives socket path)
    #[arg(long, default_value = "/nix")]
    store: PathBuf,

    /// Compare daemon responses at the protocol level
    #[arg(long)]
    compare: bool,

    /// Sleep between sends to match original timing (default: fast as possible)
    #[arg(long)]
    timing: bool,

    /// Command to replay against; everything after `--`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// Result of pre-parsing a recording.
struct PreParseResult {
    /// Negotiated protocol version from the recording.
    negotiated_version: ProtocolVersion,
    /// Client protocol version from the recording.
    client_version: ProtocolVersion,
    /// Ordered list of operations found in the recording.
    ops: Vec<Option<Op>>,
}

/// Pre-parse the recording to identify the protocol version and operation sequence.
async fn pre_parse_recording(records: &[Record]) -> Result<PreParseResult> {
    let mut client_bytes = Vec::new();
    let mut daemon_bytes = Vec::new();

    for rec in records {
        match rec.direction {
            Direction::ClientToDaemon => client_bytes.extend_from_slice(&rec.data),
            Direction::DaemonToClient => daemon_bytes.extend_from_slice(&rec.data),
        }
    }

    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));

    let info = protocol::parse_handshake(&mut client, &mut daemon).await?;
    let negotiated_version = info.negotiated_version;
    let uses_framed = negotiated_version >= ProtocolVersion::new(1, 23);

    let mut ops = Vec::new();

    loop {
        let op_code = match client.peek_u64().await? {
            Some(v) => v,
            None => break,
        };
        client.consume(8);

        let op = Op::from_u64(op_code);

        if let Some(o) = op {
            // Skip args (ignore errors for complex ops)
            let _ = protocol::skip_op_args(o, negotiated_version, &mut client).await;
            if uses_framed && protocol::op_has_client_framed_data(o) {
                let _ = client.skip_framed().await;
            }
        }

        let stderr_result = protocol::read_stderr_loop(&mut daemon).await?;
        if stderr_result.terminal == Some(StderrCode::Last) {
            if let Some(o) = op {
                let _ =
                    protocol::skip_daemon_result(o, negotiated_version, &mut daemon).await;
            }
        }

        ops.push(op);
    }

    Ok(PreParseResult {
        negotiated_version,
        client_version: info.client_version,
        ops,
    })
}

/// Send all client records to the daemon with optional timing.
///
/// Returns the writer (kept alive) so the daemon doesn't see EOF
/// on its input before the receiver has read all responses.
async fn send_client_records<W: AsyncWrite + Unpin>(
    records: &[Record],
    mut daemon_write: W,
    timing: bool,
) -> Result<W> {
    let mut prev_offset_ns = 0u64;

    for (i, rec) in records.iter().enumerate() {
        if rec.direction != Direction::ClientToDaemon {
            continue;
        }

        if timing && rec.offset_ns > prev_offset_ns {
            let gap = Duration::from_nanos(rec.offset_ns - prev_offset_ns);
            tokio::time::sleep(gap).await;
        }
        prev_offset_ns = rec.offset_ns;

        daemon_write
            .write_all(&rec.data)
            .await
            .with_context(|| format!("failed to write record {} to daemon", i))?;
        daemon_write.flush().await?;
    }

    // Return the writer to keep it alive until the caller drops it
    Ok(daemon_write)
}

/// Receive and parse all daemon responses using protocol-aware parsing.
async fn receive_daemon_responses<R: tokio::io::AsyncRead + Unpin>(
    daemon_read: R,
    pre_parse: &PreParseResult,
    compare: bool,
) -> Result<u64> {
    let mut daemon = AsyncWireReader::new(BufReader::new(daemon_read));
    let mut mismatches = 0u64;

    // Parse daemon handshake
    let live_info =
        protocol::parse_daemon_handshake(&mut daemon, pre_parse.client_version).await?;
    let live_negotiated =
        std::cmp::min(pre_parse.client_version, live_info.server_version);

    info!(
        "handshake: live daemon version {} (nix {}), negotiated {}",
        live_info.server_version,
        live_info.daemon_nix_version.as_deref().unwrap_or("unknown"),
        live_negotiated,
    );

    if compare && live_negotiated != pre_parse.negotiated_version {
        warn!(
            "negotiated version differs: recording={}, live={}",
            pre_parse.negotiated_version, live_negotiated,
        );
    }

    // Parse ops
    for (i, op) in pre_parse.ops.iter().enumerate() {
        let op_name = op
            .map(|o| o.name())
            .unwrap_or("Unknown");

        let stderr_result = match protocol::read_stderr_loop(&mut daemon).await {
            Ok(r) => r,
            Err(e) => {
                warn!("op {}: {}: failed to read stderr loop: {}", i, op_name, e);
                if compare {
                    mismatches += 1;
                }
                break;
            }
        };

        if stderr_result.terminal == Some(StderrCode::Last) {
            if let Some(o) = op {
                if let Err(e) =
                    protocol::skip_daemon_result(*o, live_negotiated, &mut daemon).await
                {
                    warn!(
                        "op {}: {}: failed to parse daemon result: {}",
                        i, op_name, e
                    );
                    if compare {
                        mismatches += 1;
                    }
                }
            }
        } else if stderr_result.terminal == Some(StderrCode::Error) {
            warn!("op {}: {}: daemon returned STDERR_ERROR", i, op_name);
            if compare {
                mismatches += 1;
            }
        }

        info!(
            "op {}: {} -> {} (stderr={})",
            i,
            op_name,
            stderr_result
                .terminal
                .map(|c| c.name().to_string())
                .unwrap_or_else(|| "(no terminal)".to_string()),
            stderr_result.count,
        );
    }

    Ok(mismatches)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let file = std::fs::File::open(&args.recording)
        .with_context(|| format!("failed to open recording: {}", args.recording.display()))?;
    let mut reader = RecordingReader::new(std::io::BufReader::new(file))?;

    let records = reader.read_all()?;

    info!(
        "loaded {} records from {}",
        records.len(),
        args.recording.display()
    );

    // Pre-parse to identify ops and protocol version
    let pre_parse = pre_parse_recording(&records).await?;
    info!(
        "pre-parsed {} operations (version {})",
        pre_parse.ops.len(),
        pre_parse.negotiated_version,
    );

    let mismatches = if args.command.is_empty() {
        // Socket mode: connect to Unix socket
        let socket = args.store.join("var/nix/daemon-socket/socket");
        let stream = UnixStream::connect(&socket)
            .await
            .with_context(|| format!("failed to connect to {}", socket.display()))?;

        info!("connected to {}", socket.display());

        let (read_half, write_half) = stream.into_split();

        // Run sender and receiver concurrently.
        // The sender returns the writer to keep it alive (preventing daemon EOF)
        // until the receiver finishes reading all responses.
        let (send_result, recv_result) = tokio::join!(
            send_client_records(&records, write_half, args.timing),
            receive_daemon_responses(read_half, &pre_parse, args.compare),
        );

        let _write_half = send_result?;
        recv_result?
    } else {
        // Command mode: spawn child, use its stdin/stdout
        let mut child = tokio::process::Command::new(&args.command[0])
            .args(&args.command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn command: {}", args.command[0]))?;

        let child_stdin = child.stdin.take().expect("child stdin was piped");
        let child_stdout = child.stdout.take().expect("child stdout was piped");

        info!("spawned command: {:?}", args.command);

        // Run sender and receiver concurrently.
        let (send_result, recv_result) = tokio::join!(
            send_client_records(&records, child_stdin, args.timing),
            receive_daemon_responses(child_stdout, &pre_parse, args.compare),
        );

        // Drop the stdin handle to let the child exit
        drop(send_result?);
        let mismatches = recv_result?;

        let status = child.wait().await.context("failed to wait for child")?;
        info!("child exited with {}", status);

        mismatches
    };

    if args.compare {
        if mismatches == 0 {
            info!("all daemon responses parsed successfully");
        } else {
            error!("{} response issues detected", mismatches);
        }
    }

    info!("replay complete ({} records)", records.len());
    Ok(())
}
