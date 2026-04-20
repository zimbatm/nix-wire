//! nix-wire-script: Human-readable protocol scripting tool.
//!
//! Three subcommands:
//! - `unpack` -- unpack .nixwire to a directory with .nwscript + data files
//! - `pack`   -- pack .nwscript + data files into .nixwire
//! - `run`    -- compile + send to daemon + evaluate expects

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use nix_wire::handshake::ProtocolVersion;
use nix_wire::protocol;
use nix_wire::script::decompile;
use nix_wire::script::expect::{evaluate_expects, evaluate_handshake_expects};
use nix_wire::script::format::{format_script, FormatOptions};
use nix_wire::script::parse::parse_script;
use nix_wire::script::serialize::{
    serialize_client_handshake, serialize_op_call, serialize_script,
};
use nix_wire::script::{terminal_name, DaemonResponse, Entry, Expect};
use nix_wire::stderr::StderrCode;
use nix_wire::wire_async::{AsyncWireReader, MemReader};
use nix_wire_recording::{Direction, Record, RecordingReader, RecordingWriter};

#[derive(Parser)]
#[command(
    name = "nix-wire-script",
    about = "Human-readable Nix daemon protocol scripting"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Unpack a .nixwire recording to a directory with .nwscript + data files
    Unpack {
        /// Path to the .nixwire recording file
        #[arg(long)]
        recording: PathBuf,

        /// Output directory. If omitted, prints script to stdout with inline data.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Maximum inline data size in bytes before extracting to a file
        /// (requires --output). Default: 64.
        #[arg(long, default_value = "64")]
        inline_threshold: usize,
    },

    /// Pack a .nwscript file into a .nixwire recording
    Pack {
        /// Path to the .nwscript script file
        #[arg(long)]
        script: PathBuf,

        /// Output path for the .nixwire recording
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Run a .nwscript against a live daemon and evaluate expects
    Run {
        /// Path to the .nwscript script file
        #[arg(long)]
        script: PathBuf,

        /// Nix store root (derives socket path)
        #[arg(long, default_value = "/nix")]
        store: PathBuf,

        /// Stop on first expect failure
        #[arg(long)]
        fail_fast: bool,

        /// Command to run against; everything after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

/// Byte offset -> timestamp mapping for one direction.
type TimestampIndex = Vec<(usize, f64)>;

/// Split records into separate client and daemon byte streams with timestamps.
fn split_records(records: &[Record]) -> (Vec<u8>, Vec<u8>, TimestampIndex) {
    let mut client_bytes = Vec::new();
    let mut daemon_bytes = Vec::new();
    let mut client_ts = Vec::new();

    for rec in records {
        match rec.direction {
            Direction::ClientToDaemon => {
                client_ts.push((client_bytes.len(), rec.offset_ns as f64 / 1_000_000.0));
                client_bytes.extend_from_slice(&rec.data);
            }
            Direction::DaemonToClient => {
                daemon_bytes.extend_from_slice(&rec.data);
            }
        }
    }

    (client_bytes, daemon_bytes, client_ts)
}

async fn cmd_unpack(
    recording_path: &PathBuf,
    output_dir: &Option<PathBuf>,
    inline_threshold: usize,
) -> Result<()> {
    let file = std::fs::File::open(recording_path)
        .with_context(|| format!("failed to open recording: {}", recording_path.display()))?;
    let mut reader = RecordingReader::new(std::io::BufReader::new(file))?;
    let records = reader.read_all()?;

    let (client_bytes, daemon_bytes, client_ts) = split_records(&records);

    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));

    let script = decompile::decompile_streams(&mut client, &mut daemon, &client_ts).await?;

    if let Some(ref dir) = output_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create output directory: {}", dir.display()))?;

        let opts = FormatOptions {
            data_dir: Some(dir.clone()),
            inline_threshold,
        };
        let text = format_script(&script, &opts);

        let script_path = dir.join("script.nwscript");
        std::fs::write(&script_path, &text)
            .with_context(|| format!("failed to write {}", script_path.display()))?;

        eprintln!("wrote {}", script_path.display());
    } else {
        let opts = FormatOptions::default();
        print!("{}", format_script(&script, &opts));
    }

    Ok(())
}

fn cmd_pack(script_path: &PathBuf, output_path: &PathBuf) -> Result<()> {
    let text = std::fs::read_to_string(script_path)
        .with_context(|| format!("failed to read script: {}", script_path.display()))?;

    let script = parse_script(&text)?;
    let base_dir = script_path.parent();

    // Build a .nixwire recording from the client bytes.
    // All records are client->daemon, timestamps from script entries.
    let mut output = std::fs::File::create(output_path)
        .with_context(|| format!("failed to create output: {}", output_path.display()))?;

    let epoch_ns = 0u64;
    let mut writer = RecordingWriter::new(&mut output, epoch_ns)?;

    let version = script.preamble.protocol_version;

    writer.write_record(&Record {
        offset_ns: 0,
        direction: Direction::ClientToDaemon,
        data: serialize_client_handshake(version, &script.preamble.client_features)?,
    })?;

    // Write each op as a separate record
    let mut offset_ns = 1_000_000u64; // 1ms
    for entry in &script.entries {
        let entry_offset = entry
            .timestamp_ms
            .map(|ms| (ms * 1_000_000.0) as u64)
            .unwrap_or(offset_ns);

        let mut op_bytes = Vec::new();
        serialize_op_call(&mut op_bytes, &entry.op_call, version, base_dir)?;

        writer.write_record(&Record {
            offset_ns: entry_offset,
            direction: Direction::ClientToDaemon,
            data: op_bytes,
        })?;

        offset_ns = entry_offset + 1_000_000; // +1ms
    }

    writer.flush()?;
    eprintln!(
        "wrote {} ops to {}",
        script.entries.len(),
        output_path.display()
    );
    Ok(())
}

async fn cmd_run(
    script_path: &PathBuf,
    store: &std::path::Path,
    fail_fast: bool,
    command: &[String],
) -> Result<()> {
    let text = std::fs::read_to_string(script_path)
        .with_context(|| format!("failed to read script: {}", script_path.display()))?;

    let script = parse_script(&text)?;
    let base_dir = script_path.parent();
    let client_bytes = serialize_script(&script, base_dir)?;
    let version = script.preamble.protocol_version;

    let preamble_expects = &script.preamble.expects;

    if command.is_empty() {
        // Socket mode
        let socket = store.join("var/nix/daemon-socket/socket");
        let stream = UnixStream::connect(&socket)
            .await
            .with_context(|| format!("failed to connect to {}", socket.display()))?;

        let (read_half, write_half) = stream.into_split();
        run_script_on_stream(
            write_half,
            read_half,
            &client_bytes,
            &script.entries,
            preamble_expects,
            version,
            fail_fast,
        )
        .await
    } else {
        // Command mode
        let mut child = tokio::process::Command::new(&command[0])
            .args(&command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn command: {}", command[0]))?;

        let child_stdin = child.stdin.take().expect("child stdin was piped");
        let child_stdout = child.stdout.take().expect("child stdout was piped");

        let result = run_script_on_stream(
            child_stdin,
            child_stdout,
            &client_bytes,
            &script.entries,
            preamble_expects,
            version,
            fail_fast,
        )
        .await;

        let _status = child.wait().await;
        result
    }
}

async fn run_script_on_stream<W, R>(
    mut writer: W,
    reader: R,
    client_bytes: &[u8],
    entries: &[Entry],
    preamble_expects: &[Expect],
    version: ProtocolVersion,
    fail_fast: bool,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    // Write and read must run concurrently: if write_all blocks on a full
    // send buffer, the daemon can't drain it until we read its responses.
    let write_fut = async {
        writer.write_all(client_bytes).await?;
        writer.flush().await?;
        anyhow::Ok(())
    };

    let read_fut = async {
        let mut daemon = AsyncWireReader::new(BufReader::new(reader));

        let live_info = protocol::parse_daemon_handshake(&mut daemon, version).await?;
        let live_version = std::cmp::min(version, live_info.server_version);

        eprintln!(
            "connected: daemon {} (protocol {})",
            live_info.daemon_nix_version.as_deref().unwrap_or("unknown"),
            live_version,
        );

        let mut total = 0u64;
        let mut passed = 0u64;
        let mut failed = 0u64;

        if !preamble_expects.is_empty() {
            let results = evaluate_handshake_expects(preamble_expects, &live_info);
            for r in &results {
                total += 1;
                if r.passed {
                    passed += 1;
                    eprintln!("  handshake PASS: {}", r.message);
                } else {
                    failed += 1;
                    eprintln!("  handshake FAIL: {}", r.message);
                    if fail_fast {
                        eprintln!("stopping (--fail-fast)");
                        std::process::exit(1);
                    }
                }
            }
        }

        for (i, entry) in entries.iter().enumerate() {
            let op = entry.op_call.op();
            let op_name = op.name();

            let (stderr_result, error_info) = protocol::read_stderr_with_error(&mut daemon).await?;

            let result = if stderr_result.terminal == Some(StderrCode::Last) {
                match protocol::read_daemon_result(op, live_version, &mut daemon).await {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("  op {i}: {op_name}: failed to parse result: {e}");
                        None
                    }
                }
            } else {
                None
            };

            let terminal = terminal_name(stderr_result.terminal);

            let response = DaemonResponse {
                terminal: terminal.clone(),
                stderr_count: stderr_result.count,
                result,
                error: error_info,
            };

            if entry.expects.is_empty() {
                eprintln!("  op {i}: {op_name} -> {terminal}");
            } else {
                let results = evaluate_expects(&entry.expects, &response);
                for r in &results {
                    total += 1;
                    if r.passed {
                        passed += 1;
                        eprintln!("  op {i}: {op_name} PASS: {}", r.message);
                    } else {
                        failed += 1;
                        eprintln!("  op {i}: {op_name} FAIL: {}", r.message);
                        if fail_fast {
                            eprintln!("stopping (--fail-fast)");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        if total > 0 {
            eprintln!("\n{passed}/{total} expects passed, {failed} failed");
            if failed > 0 {
                std::process::exit(1);
            }
        } else {
            eprintln!("\n{} ops executed (no expects)", entries.len());
        }

        anyhow::Ok(())
    };

    tokio::try_join!(write_fut, read_fut)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match &args.command {
        Command::Unpack {
            recording,
            output,
            inline_threshold,
        } => cmd_unpack(recording, output, *inline_threshold).await,
        Command::Pack { script, output } => cmd_pack(script, output),
        Command::Run {
            script,
            store,
            fail_fast,
            command,
        } => cmd_run(script, store, *fail_fast, command).await,
    }
}
