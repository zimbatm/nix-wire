//! Async protocol parsing for the Nix daemon wire protocol.
//!
//! Extracted from the decoder binary's protocol logic. All functions operate
//! on `AsyncWireReader` and contain no presentation/formatting.

use anyhow::{bail, Result};
use tokio::io::AsyncBufRead;

use crate::handshake::{self, ProtocolVersion};
use crate::ops::Op;
use crate::stderr::StderrCode;
use crate::wire_async::AsyncWireReader;

/// Information gathered during the handshake phase.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub client_version: ProtocolVersion,
    pub server_version: ProtocolVersion,
    pub negotiated_version: ProtocolVersion,
    pub client_features: Vec<String>,
    pub server_features: Vec<String>,
    pub daemon_nix_version: Option<String>,
    pub trust_status: Option<u64>,
}

/// Result of consuming the stderr message loop.
#[derive(Debug, Clone)]
pub struct StderrResult {
    /// Number of stderr messages consumed.
    pub count: u64,
    /// The terminal code (Last or Error), or None if result data follows
    /// directly without a terminal stderr code.
    pub terminal: Option<StderrCode>,
}

/// Whether an operation sends framed data from client->daemon (protocol >= 1.23).
pub fn op_has_client_framed_data(op: Op) -> bool {
    matches!(
        op,
        Op::AddToStore | Op::AddToStoreNar | Op::AddMultipleToStore | Op::AddBuildLog
    )
}

/// Parse the full handshake sequence from both streams.
///
/// Reads: magic + version exchange, feature exchange (>= 1.38),
/// post-handshake obsolete fields (cpu affinity, reserve_space),
/// daemon version (>= 1.33), trust (>= 1.35), and initial STDERR_LAST.
pub async fn parse_handshake<C, D>(
    client: &mut AsyncWireReader<C>,
    daemon: &mut AsyncWireReader<D>,
) -> Result<HandshakeInfo>
where
    C: AsyncBufRead + Unpin,
    D: AsyncBufRead + Unpin,
{
    // Client sends WORKER_MAGIC_1 + client version
    let magic1 = client.read_u64().await?;
    let client_ver_wire = client.read_u64().await?;
    let client_version = ProtocolVersion::from_wire(client_ver_wire);

    // Daemon sends WORKER_MAGIC_2 + server version
    let magic2 = daemon.read_u64().await?;
    let server_ver_wire = daemon.read_u64().await?;
    let server_version = ProtocolVersion::from_wire(server_ver_wire);

    if magic1 != handshake::WORKER_MAGIC_1 {
        bail!(
            "unexpected client magic: got {magic1:#018x}, expected {:#018x}",
            handshake::WORKER_MAGIC_1,
        );
    }
    if magic2 != handshake::WORKER_MAGIC_2 {
        bail!(
            "unexpected server magic: got {magic2:#018x}, expected {:#018x}",
            handshake::WORKER_MAGIC_2,
        );
    }

    let negotiated_version = std::cmp::min(client_version, server_version);

    // Feature exchange (>= 1.38)
    let mut client_features = Vec::new();
    let mut server_features = Vec::new();
    if negotiated_version.has_features() {
        client_features = client.read_string_set().await?;
        server_features = daemon.read_string_set().await?;
    }

    // Post-handshake obsolete fields
    // CPU affinity (>= 1.14): u64 flag, if nonzero another u64
    if negotiated_version.has_cpu_affinity() {
        let has_affinity = client.read_u64().await?;
        if has_affinity != 0 {
            let _ = client.read_u64().await?; // affinity value
        }
    }
    // reserveSpace (>= 1.11): single u64
    if negotiated_version.has_reserve_space() {
        let _ = client.read_u64().await?;
    }

    // Server sends ClientHandshakeInfo
    // >= 1.33: daemon version string
    let daemon_nix_version = if negotiated_version >= ProtocolVersion::new(1, 33) {
        Some(daemon.read_string().await?)
    } else {
        None
    };

    // >= 1.35: trust flag
    let trust_status = if negotiated_version >= ProtocolVersion::new(1, 35) {
        Some(daemon.read_u64().await?)
    } else {
        None
    };

    // After post-handshake, daemon sends STDERR_LAST before the op loop
    let code_val = daemon.read_u64().await?;
    if StderrCode::from_u64(code_val) != Some(StderrCode::Last) {
        bail!(
            "expected STDERR_LAST after handshake, got {code_val:#x}",
        );
    }

    Ok(HandshakeInfo {
        client_version,
        server_version,
        negotiated_version,
        client_features,
        server_features,
        daemon_nix_version,
        trust_status,
    })
}

/// Parse the daemon side of the handshake, given a known client version.
///
/// This is used by the replayer which knows the client version from the
/// recording but reads the daemon side from a live connection.
/// The client side bytes should already have been sent to the daemon.
pub async fn parse_daemon_handshake<D>(
    daemon: &mut AsyncWireReader<D>,
    client_version: ProtocolVersion,
) -> Result<HandshakeInfo>
where
    D: AsyncBufRead + Unpin,
{
    // Daemon sends WORKER_MAGIC_2 + server version
    let magic2 = daemon.read_u64().await?;
    let server_ver_wire = daemon.read_u64().await?;
    let server_version = ProtocolVersion::from_wire(server_ver_wire);

    if magic2 != handshake::WORKER_MAGIC_2 {
        bail!(
            "unexpected server magic: got {magic2:#018x}, expected {:#018x}",
            handshake::WORKER_MAGIC_2,
        );
    }

    let negotiated_version = std::cmp::min(client_version, server_version);

    // Feature exchange (>= 1.38): read server features
    let mut server_features = Vec::new();
    if negotiated_version.has_features() {
        server_features = daemon.read_string_set().await?;
    }

    // Server sends ClientHandshakeInfo
    // >= 1.33: daemon version string
    let daemon_nix_version = if negotiated_version >= ProtocolVersion::new(1, 33) {
        Some(daemon.read_string().await?)
    } else {
        None
    };

    // >= 1.35: trust flag
    let trust_status = if negotiated_version >= ProtocolVersion::new(1, 35) {
        Some(daemon.read_u64().await?)
    } else {
        None
    };

    // After post-handshake, daemon sends STDERR_LAST before the op loop
    let code_val = daemon.read_u64().await?;
    if StderrCode::from_u64(code_val) != Some(StderrCode::Last) {
        bail!(
            "expected STDERR_LAST after handshake, got {code_val:#x}",
        );
    }

    Ok(HandshakeInfo {
        client_version,
        server_version,
        negotiated_version,
        client_features: Vec::new(), // client features not available in this path
        server_features,
        daemon_nix_version,
        trust_status,
    })
}

/// Skip the fixed (non-framed) arguments for a known op from the client stream.
///
/// Returns a short description of what was parsed, or None if the op's args
/// are too complex to parse (BuildDerivation, AddToStoreNar).
pub async fn skip_op_args<C>(
    op: Op,
    version: ProtocolVersion,
    client: &mut AsyncWireReader<C>,
) -> Result<Option<String>>
where
    C: AsyncBufRead + Unpin,
{
    match op {
        // Single StorePath argument
        Op::IsValidPath
        | Op::QueryReferrers
        | Op::QueryDeriver
        | Op::QueryDerivationOutputs
        | Op::QueryDerivationOutputNames
        | Op::QueryDerivationOutputMap
        | Op::QueryValidDerivers
        | Op::QueryPathInfo
        | Op::EnsurePath
        | Op::AddTempRoot
        | Op::NarFromPath => {
            let path = client.read_string().await?;
            Ok(Some(path))
        }

        // Single string argument
        Op::AddIndirectRoot | Op::QueryPathFromHashPart => {
            let s = client.read_string().await?;
            Ok(Some(s))
        }

        // StorePathSet argument
        Op::QueryValidPaths => {
            let count = client.skip_string_set().await?;
            // substitute flag (>= 1.27)
            if version >= ProtocolVersion::new(1, 27) {
                client.read_u64().await?;
            }
            Ok(Some(format!("{count} paths")))
        }

        Op::QuerySubstitutablePaths => {
            let count = client.skip_string_set().await?;
            Ok(Some(format!("{count} paths")))
        }

        // SetOptions: many fields
        Op::SetOptions => {
            // keepFailed, keepGoing, tryFallback, verbosity, maxBuildJobs, maxSilentTime
            for _ in 0..6 {
                client.read_u64().await?;
            }
            // useBuildHook (>= 1.02, always true now)
            client.read_u64().await?;
            // verboseBuild (>= 1.04)
            client.read_u64().await?;
            // logType, printBuildTrace (>= 1.06, obsolete)
            client.read_u64().await?;
            client.read_u64().await?;
            // buildCores (>= 1.10)
            if version >= ProtocolVersion::new(1, 10) {
                client.read_u64().await?;
            }
            // useSubstitutes (>= 1.12)
            if version >= ProtocolVersion::new(1, 12) {
                client.read_u64().await?;
            }
            // overrides (>= 1.12): count + (name, value) pairs
            if version >= ProtocolVersion::new(1, 12) {
                let count = client.read_u64().await?;
                for _ in 0..count {
                    client.skip_string().await?; // name
                    client.skip_string().await?; // value
                }
                Ok(Some(format!("{count} overrides")))
            } else {
                Ok(Some(String::new()))
            }
        }

        // No arguments
        Op::SyncWithGC | Op::FindRoots | Op::QueryAllValidPaths | Op::OptimiseStore => {
            Ok(Some(String::new()))
        }

        // AddToStore (>= 1.25): name, camStr, refs(StringSet), repair(u64), then framed data
        Op::AddToStore => {
            if version >= ProtocolVersion::new(1, 25) {
                let name = client.read_string().await?;
                client.skip_string().await?; // camStr
                client.skip_string_set().await?; // refs
                client.read_u64().await?; // repair
                Ok(Some(name))
            } else {
                let name = client.read_string().await?;
                client.read_u64().await?; // fixed
                client.read_u64().await?; // recursive
                client.skip_string().await?; // hashAlgo
                Ok(Some(name))
            }
        }

        // AddMultipleToStore: repair(u64), dontCheckSigs(u64), then framed data
        Op::AddMultipleToStore => {
            client.read_u64().await?; // repair
            client.read_u64().await?; // dontCheckSigs
            Ok(Some(String::new()))
        }

        // AddBuildLog: drvPath(string), then framed data
        Op::AddBuildLog => {
            let path = client.read_string().await?;
            Ok(Some(path))
        }

        // BuildPaths / BuildPathsWithResults: DerivedPaths(StringSet) + mode(u64)
        Op::BuildPaths | Op::BuildPathsWithResults => {
            let count = client.skip_string_set().await?;
            client.read_u64().await?; // mode
            Ok(Some(format!("{count} paths")))
        }

        // QueryMissing: DerivedPaths(StringSet)
        Op::QueryMissing => {
            let count = client.skip_string_set().await?;
            Ok(Some(format!("{count} paths")))
        }

        // QuerySubstitutablePathInfo: path
        Op::QuerySubstitutablePathInfo => {
            let path = client.read_string().await?;
            Ok(Some(path))
        }

        // QuerySubstitutablePathInfos: StorePathSet
        Op::QuerySubstitutablePathInfos => {
            let count = client.skip_string_set().await?;
            Ok(Some(format!("{count} paths")))
        }

        // CollectGarbage: action(u64), pathsToDelete(StringSet), ignoreLiveness(u64),
        //                 maxFreed(u64), + 3 obsolete u64s
        Op::CollectGarbage => {
            client.read_u64().await?; // action
            client.skip_string_set().await?;
            client.read_u64().await?; // ignoreLiveness
            client.read_u64().await?; // maxFreed
            // obsolete fields
            client.read_u64().await?;
            client.read_u64().await?;
            client.read_u64().await?;
            Ok(Some(String::new()))
        }

        // VerifyStore: checkContents(u64), repair(u64)
        Op::VerifyStore => {
            client.read_u64().await?;
            client.read_u64().await?;
            Ok(Some(String::new()))
        }

        // AddToStoreNar: too complex
        Op::AddToStoreNar => Ok(None),

        // AddPermRoot: path(string) + gcRoot(string)
        Op::AddPermRoot => {
            client.skip_string().await?;
            client.skip_string().await?;
            Ok(Some(String::new()))
        }

        // AddSignatures: path + sigs(StringSet)
        Op::AddSignatures => {
            let path = client.read_string().await?;
            client.skip_string_set().await?;
            Ok(Some(path))
        }

        // RegisterDrvOutput, QueryRealisation: string arg
        Op::RegisterDrvOutput | Op::QueryRealisation => {
            let s = client.read_string().await?;
            Ok(Some(s))
        }

        // BuildDerivation: too complex
        Op::BuildDerivation => Ok(None),

        // AddTextToStore: suffix(string), text(string), refs(StringSet)
        Op::AddTextToStore => {
            client.skip_string().await?;
            client.skip_string().await?;
            client.skip_string_set().await?;
            Ok(Some(String::new()))
        }
    }
}

/// Read and skip the stderr message loop from the daemon stream.
///
/// Returns the count of messages consumed and the terminal code.
/// Non-terminal stderr messages (logs, activity, etc.) are consumed and discarded.
/// If the next value is not a stderr code, returns without consuming it
/// (result data follows directly).
pub async fn read_stderr_loop<D>(
    daemon: &mut AsyncWireReader<D>,
) -> Result<StderrResult>
where
    D: AsyncBufRead + Unpin,
{
    let mut count = 0u64;

    loop {
        // Peek at next u64 to check if it's a stderr code
        let peeked = match daemon.peek_u64().await? {
            Some(v) => v,
            None => {
                // EOF
                return Ok(StderrResult {
                    count,
                    terminal: None,
                });
            }
        };

        match StderrCode::from_u64(peeked) {
            Some(code) => {
                // Consume the code we peeked
                daemon.consume(8);
                count += 1;
                if code.is_terminal() {
                    return Ok(StderrResult {
                        count,
                        terminal: Some(code),
                    });
                }
                skip_stderr_payload(daemon, code).await?;
            }
            None => {
                // Not a stderr code -- result data follows
                return Ok(StderrResult {
                    count,
                    terminal: None,
                });
            }
        }
    }
}

/// Skip the payload of a non-terminal stderr message.
async fn skip_stderr_payload<D>(
    daemon: &mut AsyncWireReader<D>,
    code: StderrCode,
) -> Result<()>
where
    D: AsyncBufRead + Unpin,
{
    match code {
        StderrCode::Next | StderrCode::Write => {
            daemon.skip_string().await?;
        }
        StderrCode::Read => {
            daemon.read_u64().await?; // requested length
        }
        StderrCode::StartActivity => {
            // act, lvl, type
            daemon.read_u64().await?;
            daemon.read_u64().await?;
            daemon.read_u64().await?;
            daemon.skip_string().await?; // message
            // fields
            let nfields = daemon.read_u64().await?;
            for _ in 0..nfields {
                let ftype = daemon.read_u64().await?;
                if ftype == 0 {
                    daemon.read_u64().await?;
                } else {
                    daemon.skip_string().await?;
                }
            }
            daemon.read_u64().await?; // parent
        }
        StderrCode::StopActivity => {
            daemon.read_u64().await?; // act
        }
        StderrCode::Result => {
            daemon.read_u64().await?; // act
            daemon.read_u64().await?; // type
            let nfields = daemon.read_u64().await?;
            for _ in 0..nfields {
                let ftype = daemon.read_u64().await?;
                if ftype == 0 {
                    daemon.read_u64().await?;
                } else {
                    daemon.skip_string().await?;
                }
            }
        }
        // Terminal codes handled by caller, but be safe
        _ => {}
    }
    Ok(())
}

/// Skip the daemon's result data after STDERR_LAST for a given op.
pub async fn skip_daemon_result<D>(
    op: Op,
    version: ProtocolVersion,
    daemon: &mut AsyncWireReader<D>,
) -> Result<()>
where
    D: AsyncBufRead + Unpin,
{
    match op {
        // Ops that return nothing (just STDERR_LAST, no result data)
        Op::SetOptions | Op::RegisterDrvOutput | Op::AddMultipleToStore | Op::AddToStoreNar => {}

        // Ops that return a single u64
        Op::IsValidPath
        | Op::VerifyStore
        | Op::AddTempRoot
        | Op::AddIndirectRoot
        | Op::EnsurePath
        | Op::SyncWithGC
        | Op::OptimiseStore
        | Op::AddSignatures
        | Op::AddBuildLog => {
            daemon.read_u64().await?;
        }

        // AddPermRoot returns a string
        Op::AddPermRoot => {
            daemon.skip_string().await?;
        }

        // Ops that return a single store path string
        Op::AddTextToStore | Op::QueryDeriver | Op::QueryPathFromHashPart => {
            daemon.skip_string().await?;
        }

        // AddToStore: >= 1.25 returns ValidPathInfo, older returns StorePath
        Op::AddToStore => {
            if version >= ProtocolVersion::new(1, 25) {
                daemon.skip_string().await?; // path
                skip_unkeyed_valid_path_info(daemon, version).await?;
            } else {
                daemon.skip_string().await?; // StorePath
            }
        }

        // NarFromPath: sends NAR as framed data (>= 1.23)
        Op::NarFromPath => {
            if version >= ProtocolVersion::new(1, 23) {
                daemon.skip_framed().await?;
            }
        }

        // StorePathSet results
        Op::QueryReferrers
        | Op::QueryAllValidPaths
        | Op::QueryValidDerivers
        | Op::QuerySubstitutablePaths
        | Op::QueryValidPaths
        | Op::QueryDerivationOutputs
        | Op::QueryDerivationOutputNames => {
            daemon.skip_string_set().await?;
        }

        // QueryDerivationOutputMap: count + (name, path) pairs
        Op::QueryDerivationOutputMap => {
            let count = daemon.read_u64().await?;
            for _ in 0..count {
                daemon.skip_string().await?;
                daemon.skip_string().await?;
            }
        }

        // FindRoots: count + (path, path) pairs
        Op::FindRoots => {
            let count = daemon.read_u64().await?;
            for _ in 0..count {
                daemon.skip_string().await?;
                daemon.skip_string().await?;
            }
        }

        // QueryPathInfo: bool(valid) + if valid: UnkeyedValidPathInfo
        Op::QueryPathInfo => {
            let valid = daemon.read_u64().await?;
            if valid != 0 {
                skip_unkeyed_valid_path_info(daemon, version).await?;
            }
        }

        // BuildPaths: returns u64(1) on success
        Op::BuildPaths => {
            daemon.read_u64().await?;
        }

        // CollectGarbage: bytesFreed + 2 obsolete u64s
        Op::CollectGarbage => {
            daemon.read_u64().await?;
            daemon.read_u64().await?;
            daemon.read_u64().await?;
        }

        // QuerySubstitutablePathInfo: bool + if true: deriver, refs, downloadSize, narSize
        Op::QuerySubstitutablePathInfo => {
            let valid = daemon.read_u64().await?;
            if valid != 0 {
                daemon.skip_string().await?; // deriver
                daemon.skip_string_set().await?; // refs
                daemon.read_u64().await?; // downloadSize
                daemon.read_u64().await?; // narSize
            }
        }

        // QuerySubstitutablePathInfos: count + (path, deriver, refs, downloadSize, narSize)
        Op::QuerySubstitutablePathInfos => {
            let count = daemon.read_u64().await?;
            for _ in 0..count {
                daemon.skip_string().await?;
                daemon.skip_string().await?;
                daemon.skip_string_set().await?;
                daemon.read_u64().await?;
                daemon.read_u64().await?;
            }
        }

        // QueryMissing: willBuild, willSubstitute, unknown (StringSets), downloadSize, narSize
        Op::QueryMissing => {
            daemon.skip_string_set().await?;
            daemon.skip_string_set().await?;
            daemon.skip_string_set().await?;
            daemon.read_u64().await?;
            daemon.read_u64().await?;
        }

        // BuildDerivation: returns a BuildResult
        Op::BuildDerivation => {
            skip_build_result(daemon, version).await?;
        }

        // BuildPathsWithResults: count + for each: DerivedPath(string) + BuildResult
        Op::BuildPathsWithResults => {
            let count = daemon.read_u64().await?;
            for _ in 0..count {
                daemon.skip_string().await?; // DerivedPath
                skip_build_result(daemon, version).await?;
            }
        }

        // QueryRealisation: StringSet
        Op::QueryRealisation => {
            daemon.skip_string_set().await?;
        }
    }
    Ok(())
}

/// Skip a BuildResult on the wire.
async fn skip_build_result<D>(
    daemon: &mut AsyncWireReader<D>,
    version: ProtocolVersion,
) -> Result<()>
where
    D: AsyncBufRead + Unpin,
{
    daemon.read_u64().await?; // status
    daemon.skip_string().await?; // errorMsg
    if version >= ProtocolVersion::new(1, 29) {
        daemon.read_u64().await?; // timesBuilt
        daemon.read_u64().await?; // isNonDeterministic
        daemon.read_u64().await?; // startTime
        daemon.read_u64().await?; // stopTime
    }
    if version >= ProtocolVersion::new(1, 37) {
        skip_optional_duration(daemon).await?; // cpuUser
        skip_optional_duration(daemon).await?; // cpuSystem
    }
    if version >= ProtocolVersion::new(1, 28) {
        // DrvOutputs = map<DrvOutput, Realisation>
        let count = daemon.read_u64().await?;
        for _ in 0..count {
            daemon.skip_string().await?; // DrvOutput
            daemon.skip_string().await?; // Realisation (JSON)
        }
    }
    Ok(())
}

/// Skip optional<microseconds>: u64(flag) [+ u64(count) if flag != 0]
async fn skip_optional_duration<D>(
    daemon: &mut AsyncWireReader<D>,
) -> Result<()>
where
    D: AsyncBufRead + Unpin,
{
    let flag = daemon.read_u64().await?;
    if flag != 0 {
        daemon.read_u64().await?; // microseconds count
    }
    Ok(())
}

/// Skip UnkeyedValidPathInfo fields.
async fn skip_unkeyed_valid_path_info<D>(
    daemon: &mut AsyncWireReader<D>,
    version: ProtocolVersion,
) -> Result<()>
where
    D: AsyncBufRead + Unpin,
{
    daemon.skip_string().await?; // deriver
    daemon.skip_string().await?; // narHash
    daemon.skip_string_set().await?; // references
    daemon.read_u64().await?; // registrationTime
    daemon.read_u64().await?; // narSize
    if version >= ProtocolVersion::new(1, 16) {
        daemon.read_u64().await?; // ultimate
        daemon.skip_string_set().await?; // sigs
        daemon.skip_string().await?; // ca
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{WORKER_MAGIC_1, WORKER_MAGIC_2};
    use tokio::io::BufReader;

    /// Build a minimal handshake byte stream for client and daemon sides.
    fn build_handshake_streams(
        client_ver: ProtocolVersion,
        server_ver: ProtocolVersion,
    ) -> (Vec<u8>, Vec<u8>) {
        let negotiated = std::cmp::min(client_ver, server_ver);
        let mut client_bytes = Vec::new();
        let mut daemon_bytes = Vec::new();

        // Magic + version
        client_bytes.extend_from_slice(&WORKER_MAGIC_1.to_le_bytes());
        client_bytes.extend_from_slice(&client_ver.to_wire().to_le_bytes());
        daemon_bytes.extend_from_slice(&WORKER_MAGIC_2.to_le_bytes());
        daemon_bytes.extend_from_slice(&server_ver.to_wire().to_le_bytes());

        // Feature exchange (>= 1.38): empty sets
        if negotiated.has_features() {
            // client features: count=0
            client_bytes.extend_from_slice(&0u64.to_le_bytes());
            // server features: count=0
            daemon_bytes.extend_from_slice(&0u64.to_le_bytes());
        }

        // CPU affinity (>= 1.14): flag=0
        if negotiated.has_cpu_affinity() {
            client_bytes.extend_from_slice(&0u64.to_le_bytes());
        }

        // reserveSpace (>= 1.11): value=0
        if negotiated.has_reserve_space() {
            client_bytes.extend_from_slice(&0u64.to_le_bytes());
        }

        // daemon version string (>= 1.33)
        if negotiated >= ProtocolVersion::new(1, 33) {
            // "2.24.0" -> len=6 + data + 2 bytes padding
            let ver = b"2.24.0";
            daemon_bytes.extend_from_slice(&(ver.len() as u64).to_le_bytes());
            daemon_bytes.extend_from_slice(ver);
            daemon_bytes.extend_from_slice(&[0, 0]); // padding to 8
        }

        // trust (>= 1.35): trusted=1
        if negotiated >= ProtocolVersion::new(1, 35) {
            daemon_bytes.extend_from_slice(&1u64.to_le_bytes());
        }

        // STDERR_LAST
        daemon_bytes.extend_from_slice(&(StderrCode::Last as u64).to_le_bytes());

        (client_bytes, daemon_bytes)
    }

    #[tokio::test]
    async fn parse_handshake_v1_38() {
        let client_ver = ProtocolVersion::new(1, 38);
        let server_ver = ProtocolVersion::new(1, 38);
        let (client_bytes, daemon_bytes) = build_handshake_streams(client_ver, server_ver);

        let mut client = AsyncWireReader::new(BufReader::new(&client_bytes[..]));
        let mut daemon = AsyncWireReader::new(BufReader::new(&daemon_bytes[..]));

        let info = parse_handshake(&mut client, &mut daemon).await.unwrap();
        assert_eq!(info.client_version, client_ver);
        assert_eq!(info.server_version, server_ver);
        assert_eq!(info.negotiated_version, ProtocolVersion::new(1, 38));
        assert!(info.client_features.is_empty());
        assert!(info.server_features.is_empty());
        assert_eq!(info.daemon_nix_version.as_deref(), Some("2.24.0"));
        assert_eq!(info.trust_status, Some(1));
    }

    #[tokio::test]
    async fn parse_handshake_v1_37() {
        let client_ver = ProtocolVersion::new(1, 37);
        let server_ver = ProtocolVersion::new(1, 37);
        let (client_bytes, daemon_bytes) = build_handshake_streams(client_ver, server_ver);

        let mut client = AsyncWireReader::new(BufReader::new(&client_bytes[..]));
        let mut daemon = AsyncWireReader::new(BufReader::new(&daemon_bytes[..]));

        let info = parse_handshake(&mut client, &mut daemon).await.unwrap();
        assert_eq!(info.negotiated_version, ProtocolVersion::new(1, 37));
        // no features in 1.37
        assert!(info.client_features.is_empty());
        assert!(info.server_features.is_empty());
        assert_eq!(info.daemon_nix_version.as_deref(), Some("2.24.0"));
        assert_eq!(info.trust_status, Some(1));
    }

    #[tokio::test]
    async fn op_has_framed_data() {
        assert!(op_has_client_framed_data(Op::AddToStore));
        assert!(op_has_client_framed_data(Op::AddToStoreNar));
        assert!(op_has_client_framed_data(Op::AddMultipleToStore));
        assert!(op_has_client_framed_data(Op::AddBuildLog));
        assert!(!op_has_client_framed_data(Op::IsValidPath));
        assert!(!op_has_client_framed_data(Op::SetOptions));
    }

    #[tokio::test]
    async fn stderr_loop_last() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(StderrCode::Last as u64).to_le_bytes());
        let mut daemon = AsyncWireReader::new(BufReader::new(&buf[..]));
        let result = read_stderr_loop(&mut daemon).await.unwrap();
        assert_eq!(result.count, 1);
        assert_eq!(result.terminal, Some(StderrCode::Last));
    }

    #[tokio::test]
    async fn stderr_loop_with_next_then_last() {
        let mut buf = Vec::new();
        // STDERR_NEXT + a log string "hello"
        buf.extend_from_slice(&(StderrCode::Next as u64).to_le_bytes());
        buf.extend_from_slice(&5u64.to_le_bytes());
        buf.extend_from_slice(b"hello");
        buf.extend_from_slice(&[0, 0, 0]); // padding
        // STDERR_LAST
        buf.extend_from_slice(&(StderrCode::Last as u64).to_le_bytes());

        let mut daemon = AsyncWireReader::new(BufReader::new(&buf[..]));
        let result = read_stderr_loop(&mut daemon).await.unwrap();
        assert_eq!(result.count, 2);
        assert_eq!(result.terminal, Some(StderrCode::Last));
    }

    #[tokio::test]
    async fn stderr_loop_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(StderrCode::Error as u64).to_le_bytes());
        let mut daemon = AsyncWireReader::new(BufReader::new(&buf[..]));
        let result = read_stderr_loop(&mut daemon).await.unwrap();
        assert_eq!(result.count, 1);
        assert_eq!(result.terminal, Some(StderrCode::Error));
    }

    #[tokio::test]
    async fn stderr_loop_no_terminal() {
        // Result data follows directly (non-stderr code value)
        let mut buf = Vec::new();
        buf.extend_from_slice(&42u64.to_le_bytes()); // not a stderr code
        let mut daemon = AsyncWireReader::new(BufReader::new(&buf[..]));
        let result = read_stderr_loop(&mut daemon).await.unwrap();
        assert_eq!(result.count, 0);
        assert_eq!(result.terminal, None);
        // The 42 should not have been consumed
        assert_eq!(daemon.read_u64().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn skip_op_args_is_valid_path() {
        let mut buf = Vec::new();
        let path = "/nix/store/aaaabbbbccccddddeeeeffffgggghhhh-foo";
        buf.extend_from_slice(&(path.len() as u64).to_le_bytes());
        buf.extend_from_slice(path.as_bytes());
        // padding to 8-byte boundary
        let padding = (8 - (path.len() % 8)) % 8;
        buf.extend_from_slice(&vec![0u8; padding]);

        let mut client = AsyncWireReader::new(BufReader::new(&buf[..]));
        let version = ProtocolVersion::new(1, 37);
        let result = skip_op_args(Op::IsValidPath, version, &mut client)
            .await
            .unwrap();
        assert_eq!(result.as_deref(), Some(path));
    }

    #[tokio::test]
    async fn skip_daemon_result_is_valid_path() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_le_bytes()); // valid=true
        let mut daemon = AsyncWireReader::new(BufReader::new(&buf[..]));
        let version = ProtocolVersion::new(1, 37);
        skip_daemon_result(Op::IsValidPath, version, &mut daemon)
            .await
            .unwrap();
    }
}
