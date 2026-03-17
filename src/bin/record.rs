//! nix-wire-record: Proxy/recorder for the Nix daemon socket.
//!
//! Interposes on the daemon unix socket, recording all bidirectional
//! traffic with timestamps for later analysis.
//!
//! Two modes:
//! - Socket mode (default): proxy the daemon Unix socket
//! - Command mode: wrap a child process (e.g., `nix-daemon --stdio`)

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use nix_wire::recording::{Direction, Record, RecordingWriter};

#[derive(Parser)]
#[command(
    name = "nix-wire-record",
    about = "Record Nix daemon wire protocol sessions"
)]
struct Args {
    /// Nix store root (derives socket and output paths)
    #[arg(long, default_value = "/nix")]
    store: PathBuf,

    /// Override recording output directory
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Command to wrap (command mode); everything after `--`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

impl Args {
    fn output_dir(&self) -> PathBuf {
        self.output_dir
            .clone()
            .unwrap_or_else(|| self.store.join("var/nix/nix-wire"))
    }
}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Scan `output_dir` for existing `NNNN.nixwire` files and return the next
/// sequential path, avoiding collisions across restarts and concurrent processes.
fn next_recording_path(output_dir: &Path) -> Result<PathBuf> {
    let mut next_id: u64 = 0;

    if output_dir.exists() {
        for entry in std::fs::read_dir(output_dir)
            .with_context(|| format!("failed to read output dir: {}", output_dir.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".nixwire") {
                if let Ok(id) = stem.parse::<u64>() {
                    next_id = next_id.max(id + 1);
                }
            }
        }
    }

    // Incorporate session counter to avoid races between concurrent callers
    let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    next_id = next_id.max(counter);

    Ok(output_dir.join(format!("{next_id:04}.nixwire")))
}

/// Copy from `reader` to `writer`, recording each chunk with the given direction.
async fn copy_and_record(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    direction: Direction,
    recording: Arc<Mutex<RecordingWriter<std::io::BufWriter<std::fs::File>>>>,
    epoch_ns: u64,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                warn!("{} read error: {}", direction, e);
                break;
            }
        };

        let offset_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            - epoch_ns;

        let record = Record {
            offset_ns,
            direction,
            data: buf[..n].to_vec(),
        };

        {
            let mut w = recording.lock().await;
            if let Err(e) = w.write_record(&record) {
                error!("failed to write {} record: {}", direction, e);
            }
            let _ = w.flush();
        }

        if let Err(e) = writer.write_all(&buf[..n]).await {
            warn!("{} write error: {}", direction, e);
            break;
        }
    }
}

/// Bidirectional copy+tee loop: forwards data between client and daemon while
/// recording all traffic.
async fn proxy_and_record(
    client_read: impl AsyncRead + Unpin + Send + 'static,
    client_write: impl AsyncWrite + Unpin + Send + 'static,
    daemon_read: impl AsyncRead + Unpin + Send + 'static,
    daemon_write: impl AsyncWrite + Unpin + Send + 'static,
    writer: Arc<Mutex<RecordingWriter<std::io::BufWriter<std::fs::File>>>>,
    epoch_ns: u64,
) {
    let c2d = tokio::spawn(copy_and_record(
        client_read,
        daemon_write,
        Direction::ClientToDaemon,
        writer.clone(),
        epoch_ns,
    ));
    let d2c = tokio::spawn(copy_and_record(
        daemon_read,
        client_write,
        Direction::DaemonToClient,
        writer,
        epoch_ns,
    ));

    let _ = tokio::join!(c2d, d2c);
}

async fn handle_connection(
    client: UnixStream,
    orig_path: &Path,
    output_dir: &Path,
    session_id: u64,
) -> Result<()> {
    let epoch_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let recording_path = output_dir.join(format!("{session_id:04}.nixwire"));
    let file = std::fs::File::create(&recording_path)?;
    let writer = RecordingWriter::new(std::io::BufWriter::new(file), epoch_ns)?;
    let writer = Arc::new(Mutex::new(writer));

    info!(
        "session {}: recording to {}",
        session_id,
        recording_path.display()
    );

    // Connect to the real daemon
    let daemon = UnixStream::connect(orig_path)
        .await
        .context("failed to connect to upstream daemon")?;

    let (client_read, client_write) = client.into_split();
    let (daemon_read, daemon_write) = daemon.into_split();

    proxy_and_record(
        client_read,
        client_write,
        daemon_read,
        daemon_write,
        writer,
        epoch_ns,
    )
    .await;

    info!("session {}: connection closed", session_id);
    Ok(())
}

async fn run_socket_mode(args: &Args) -> Result<()> {
    let socket_dir = args.store.join("var/nix/daemon-socket");
    let output_dir = args.output_dir();

    let socket_path = socket_dir.join("socket");
    let orig_path = socket_dir.join("socket.orig");

    // Create output directory
    tokio::fs::create_dir_all(&output_dir)
        .await
        .context("failed to create output directory")?;

    // Move socket -> socket.orig (skip if already done from a previous crash)
    if orig_path.exists() {
        warn!(
            "socket.orig already exists (previous crash?), reusing: {}",
            orig_path.display()
        );
    } else {
        tokio::fs::rename(&socket_path, &orig_path)
            .await
            .with_context(|| {
                format!(
                    "failed to rename {} -> {}",
                    socket_path.display(),
                    orig_path.display()
                )
            })?;
        info!("moved {} -> {}", socket_path.display(), orig_path.display());
    }

    // Listen on the original socket path
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;

    // Try to match permissions of the original socket
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666));
    }

    info!("listening on {}", socket_path.display());
    info!(
        "proxying to {}, writing recordings to {}",
        orig_path.display(),
        output_dir.display()
    );

    let orig_path_clone = orig_path.clone();
    let output_dir_clone = output_dir.clone();

    // Spawn connection handler
    let accept_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((client_stream, _addr)) => {
                    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
                    let orig = orig_path_clone.clone();
                    let out_dir = output_dir_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(client_stream, &orig, &out_dir, session_id).await
                        {
                            error!("session {}: {:#}", session_id, e);
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {}", e);
                }
            }
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("received SIGINT, shutting down...");
        }
        _ = async {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
            sigterm.recv().await;
        } => {
            info!("received SIGTERM, shutting down...");
        }
    }

    // Abort the accept loop
    accept_handle.abort();

    // Give active connections a moment to drain
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Restore socket
    if let Err(e) = tokio::fs::remove_file(&socket_path).await {
        warn!("failed to remove proxy socket: {}", e);
    }
    if let Err(e) = tokio::fs::rename(&orig_path, &socket_path).await {
        error!(
            "CRITICAL: failed to restore socket: {}. Manual fix needed: mv {} {}",
            e,
            orig_path.display(),
            socket_path.display()
        );
    } else {
        info!(
            "restored {} -> {}",
            orig_path.display(),
            socket_path.display()
        );
    }

    Ok(())
}

async fn run_command_mode(args: &Args) -> Result<()> {
    let output_dir = args.output_dir();

    // Create output directory
    tokio::fs::create_dir_all(&output_dir)
        .await
        .context("failed to create output directory")?;

    let recording_path = next_recording_path(&output_dir)?;

    let epoch_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let file = std::fs::File::create(&recording_path)?;
    let writer = RecordingWriter::new(std::io::BufWriter::new(file), epoch_ns)?;
    let writer = Arc::new(Mutex::new(writer));

    info!("recording to {}", recording_path.display());
    info!("spawning command: {:?}", args.command);

    // Spawn child process
    let mut child = tokio::process::Command::new(&args.command[0])
        .args(&args.command[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn command: {}", args.command[0]))?;

    let child_stdin = child.stdin.take().expect("child stdin was piped");
    let child_stdout = child.stdout.take().expect("child stdout was piped");

    let client_read = tokio::io::stdin();
    let client_write = tokio::io::stdout();

    proxy_and_record(
        client_read,
        client_write,
        child_stdout,
        child_stdin,
        writer,
        epoch_ns,
    )
    .await;

    let status = child.wait().await.context("failed to wait for child")?;
    info!("child exited with {}", status);

    // Propagate exit code
    std::process::exit(status.code().unwrap_or(1));
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

    if args.command.is_empty() {
        run_socket_mode(&args).await
    } else {
        run_command_mode(&args).await
    }
}
