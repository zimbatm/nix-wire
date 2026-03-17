//! nix-wire-decode: Protocol decoder for recorded Nix daemon sessions.
//!
//! Parses the bidirectional protocol stream using the shared async protocol
//! library and prints human-readable operation names, timing, and store paths.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use serde::Serialize;

use nix_wire::handshake::ProtocolVersion;
use nix_wire::ops::Op;
use nix_wire::protocol;
use nix_wire::recording::{Direction, RecordingReader};
use nix_wire::stderr::StderrCode;
use nix_wire::wire_async::{AsyncWireReader, MemReader};

#[derive(Parser)]
#[command(
    name = "nix-wire-decode",
    about = "Decode Nix daemon wire protocol recordings"
)]
struct Args {
    /// Path to the .nixwire recording file
    #[arg(long)]
    recording: PathBuf,

    /// Output format
    #[arg(long, default_value = "text")]
    format: OutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// Byte offset -> timestamp mapping for one direction.
type TimestampIndex = Vec<(usize, u64)>;

/// Data split by direction, with timestamp indexes.
struct SplitRecords {
    client_bytes: Vec<u8>,
    daemon_bytes: Vec<u8>,
    client_ts: TimestampIndex,
    daemon_ts: TimestampIndex,
}

/// Split records into separate client and daemon byte streams.
fn split_records(records: &[nix_wire::recording::Record]) -> SplitRecords {
    let mut result = SplitRecords {
        client_bytes: Vec::new(),
        daemon_bytes: Vec::new(),
        client_ts: Vec::new(),
        daemon_ts: Vec::new(),
    };

    for rec in records {
        match rec.direction {
            Direction::ClientToDaemon => {
                result
                    .client_ts
                    .push((result.client_bytes.len(), rec.offset_ns));
                result.client_bytes.extend_from_slice(&rec.data);
            }
            Direction::DaemonToClient => {
                result
                    .daemon_ts
                    .push((result.daemon_bytes.len(), rec.offset_ns));
                result.daemon_bytes.extend_from_slice(&rec.data);
            }
        }
    }

    result
}

/// Look up the timestamp for a byte offset using a timestamp index.
fn lookup_timestamp(ts_index: &[(usize, u64)], byte_offset: usize) -> u64 {
    if ts_index.is_empty() {
        return 0;
    }
    match ts_index.binary_search_by_key(&byte_offset, |&(off, _)| off) {
        Ok(i) => ts_index[i].1,
        Err(0) => ts_index[0].1,
        Err(i) => ts_index[i - 1].1,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let file = std::fs::File::open(&args.recording)?;
    let mut reader = RecordingReader::new(std::io::BufReader::new(file))?;

    let header = *reader.header();
    let records = reader.read_all()?;

    match args.format {
        OutputFormat::Text => decode_text(&header, &records).await,
        OutputFormat::Json => decode_json(&header, &records),
    }
}

async fn decode_text(
    header: &nix_wire::recording::Header,
    records: &[nix_wire::recording::Record],
) -> Result<()> {
    println!("=== Nix Wire Protocol Recording ===");
    println!(
        "Session start: {} (epoch_ns: {})",
        format_timestamp(header.epoch_ns),
        header.epoch_ns
    );
    println!("Records: {}", records.len());
    println!();

    let split = split_records(records);

    let mut client = AsyncWireReader::new(MemReader::new(split.client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(split.daemon_bytes));

    // Phase 1: Handshake
    let info = protocol::parse_handshake(&mut client, &mut daemon).await?;
    let negotiated_version = info.negotiated_version;

    println!("--- Handshake ---");
    println!("  Client version: {}", info.client_version);
    println!("  Server version: {}", info.server_version);
    println!("  Negotiated version: {negotiated_version}");
    if !info.client_features.is_empty() || !info.server_features.is_empty() {
        println!("  Client features: {:?}", info.client_features);
        println!("  Server features: {:?}", info.server_features);
    }
    if let Some(ref ver) = info.daemon_nix_version {
        println!("  Daemon Nix version: {ver}");
    }
    if let Some(trust) = info.trust_status {
        let trust_str = match trust {
            0 => "unknown",
            1 => "trusted",
            2 => "not trusted",
            _ => "invalid",
        };
        println!("  Remote trusts us: {trust_str}");
    }
    println!();

    // Phase 2: Operations
    println!("--- Operations ---");

    let uses_framed = negotiated_version >= ProtocolVersion::new(1, 23);

    loop {
        let consumed_before = client.inner_ref().position();

        // Try to read an op code from the client stream
        let op_code = match client.peek_u64().await? {
            Some(v) => v,
            None => break, // no more ops
        };
        client.consume(8);

        // Get timestamp for op start from the client timestamp index
        let op_start_ns = lookup_timestamp(&split.client_ts, consumed_before);

        // Guard: detect likely desynchronization
        if op_code == 0 || op_code > 64 {
            eprintln!(
                "SYNC WARNING: op code {op_code} ({op_code:#x}) at byte offset {consumed_before} \
                 is outside valid range (1..=47)"
            );
            if let Some(stderr_code) = StderrCode::from_u64(op_code) {
                eprintln!(
                    "SYNC WARNING: value {op_code:#x} matches StderrCode::{}, \
                     possible client/daemon stream confusion",
                    stderr_code.name(),
                );
            }
        }

        let op = Op::from_u64(op_code);
        let op_name = op
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("Unknown({})", op_code));

        // Skip fixed arguments for the op
        let mut arg_info = None;
        if let Some(o) = op {
            match protocol::skip_op_args(o, negotiated_version, &mut client).await {
                Ok(info) => arg_info = info,
                Err(e) => {
                    eprintln!(
                        "SYNC WARNING: failed to parse args for {} ({}): {}",
                        o.name(),
                        op_code,
                        e,
                    );
                }
            }
        } else {
            eprintln!(
                "SYNC WARNING: unknown op code {op_code} ({op_code:#x}), \
                 args not consumed, stream may be desynchronized"
            );
        }

        // For ops with framed data (>= 1.23), skip the framed chunks
        let mut framed_bytes = None;
        if uses_framed {
            if let Some(o) = op {
                if protocol::op_has_client_framed_data(o) {
                    match client.skip_framed().await {
                        Ok(total) => framed_bytes = Some(total),
                        Err(e) => {
                            eprintln!(
                                "SYNC WARNING: failed to skip framed data for {}: {}",
                                o.name(),
                                e,
                            );
                        }
                    }
                }
            }
        }

        let request_bytes = client.inner_ref().position() - consumed_before;

        // Get daemon position before stderr for timing
        let daemon_pos_before = daemon.inner_ref().position();

        // Read stderr response from daemon
        let stderr_result = protocol::read_stderr_loop(&mut daemon).await?;

        // Skip daemon result after STDERR_LAST
        if stderr_result.terminal == Some(StderrCode::Last) {
            if let Some(o) = op {
                if let Err(e) =
                    protocol::skip_daemon_result(o, negotiated_version, &mut daemon).await
                {
                    eprintln!(
                        "SYNC WARNING: incomplete daemon result for {} ({}): {}",
                        o.name(),
                        op_code,
                        e,
                    );
                }
            }
        }

        let result_str = match stderr_result.terminal {
            Some(code) => code.name().to_string(),
            None => "(no terminal)".to_string(),
        };

        // Get op end timestamp from daemon timestamp index
        let daemon_pos_after = daemon.inner_ref().position();
        let op_end_ns = if daemon_pos_after > daemon_pos_before {
            lookup_timestamp(&split.daemon_ts, daemon_pos_after.saturating_sub(1))
        } else {
            op_start_ns
        };
        let duration = Duration::from_nanos(op_end_ns.saturating_sub(op_start_ns));

        let mut extra = String::new();
        if let Some(ref info) = arg_info {
            if !info.is_empty() {
                extra.push_str(&format!("  {info}"));
            }
        }
        if let Some(n) = framed_bytes {
            extra.push_str(&format!("  framed={n}B"));
        }

        println!(
            "  [{:>10.3}ms] {:<35} req={:>6}B  stderr={:<3}  {:>8.3}ms  {}{}",
            op_start_ns as f64 / 1_000_000.0,
            op_name,
            request_bytes,
            stderr_result.count,
            duration.as_secs_f64() * 1000.0,
            result_str,
            extra,
        );
    }

    // Summary
    if let (Some(first), Some(last)) = (records.first(), records.last()) {
        let total_duration = Duration::from_nanos(last.offset_ns - first.offset_ns);
        let total_c2d: usize = records
            .iter()
            .filter(|r| r.direction == Direction::ClientToDaemon)
            .map(|r| r.data.len())
            .sum();
        let total_d2c: usize = records
            .iter()
            .filter(|r| r.direction == Direction::DaemonToClient)
            .map(|r| r.data.len())
            .sum();
        println!();
        println!("--- Summary ---");
        println!(
            "  Total duration: {:.3}ms",
            total_duration.as_secs_f64() * 1000.0
        );
        println!("  Client -> Daemon: {} bytes", total_c2d);
        println!("  Daemon -> Client: {} bytes", total_d2c);
        println!("  Total records: {}", records.len());
    }

    Ok(())
}

fn decode_json(
    header: &nix_wire::recording::Header,
    records: &[nix_wire::recording::Record],
) -> Result<()> {
    let total_c2d: usize = records
        .iter()
        .filter(|r| r.direction == Direction::ClientToDaemon)
        .map(|r| r.data.len())
        .sum();
    let total_d2c: usize = records
        .iter()
        .filter(|r| r.direction == Direction::DaemonToClient)
        .map(|r| r.data.len())
        .sum();

    #[derive(Serialize)]
    struct Summary {
        epoch_ns: u64,
        record_count: usize,
        client_to_daemon_bytes: usize,
        daemon_to_client_bytes: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        total_duration_ms: Option<f64>,
        records: Vec<RecordSummary>,
    }

    #[derive(Serialize)]
    struct RecordSummary {
        offset_ms: f64,
        direction: String,
        bytes: usize,
    }

    let record_summaries: Vec<RecordSummary> = records
        .iter()
        .map(|r| RecordSummary {
            offset_ms: r.offset_ns as f64 / 1_000_000.0,
            direction: r.direction.label().to_string(),
            bytes: r.data.len(),
        })
        .collect();

    let total_duration = records
        .first()
        .zip(records.last())
        .map(|(f, l)| (l.offset_ns - f.offset_ns) as f64 / 1_000_000.0);

    let summary = Summary {
        epoch_ns: header.epoch_ns,
        record_count: records.len(),
        client_to_daemon_bytes: total_c2d,
        daemon_to_client_bytes: total_d2c,
        total_duration_ms: total_duration,
        records: record_summaries,
    };

    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn format_timestamp(epoch_ns: u64) -> String {
    let secs = epoch_ns / 1_000_000_000;
    let nanos = epoch_ns % 1_000_000_000;
    format!("{secs}.{nanos:09}")
}
