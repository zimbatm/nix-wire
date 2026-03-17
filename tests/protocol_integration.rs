//! Integration tests for async protocol parsing against real recordings.

use nix_wire::handshake::ProtocolVersion;
use nix_wire::ops::Op;
use nix_wire::protocol;
use nix_wire::recording::{Direction, RecordingReader};
use nix_wire::stderr::StderrCode;
use nix_wire::wire_async::{AsyncWireReader, MemReader};

/// Split records into client and daemon byte streams.
fn split_directions(
    records: &[nix_wire::recording::Record],
) -> (Vec<u8>, Vec<u8>) {
    let mut client_bytes = Vec::new();
    let mut daemon_bytes = Vec::new();
    for rec in records {
        match rec.direction {
            Direction::ClientToDaemon => client_bytes.extend_from_slice(&rec.data),
            Direction::DaemonToClient => daemon_bytes.extend_from_slice(&rec.data),
        }
    }
    (client_bytes, daemon_bytes)
}

/// Load a fixture recording and return its records.
fn load_fixture(name: &str) -> Vec<nix_wire::recording::Record> {
    let path = format!(
        "{}/tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name,
    );
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("failed to open fixture {}: {}", path, e));
    let mut reader = RecordingReader::new(std::io::BufReader::new(file)).unwrap();
    reader.read_all().unwrap()
}

#[tokio::test]
async fn parse_handshake_from_recording() {
    let records = load_fixture("simple_session.nixwire");
    let (client_bytes, daemon_bytes) = split_directions(&records);

    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));

    let info = protocol::parse_handshake(&mut client, &mut daemon)
        .await
        .unwrap();

    assert_eq!(info.client_version, ProtocolVersion::new(1, 38));
    assert_eq!(info.server_version, ProtocolVersion::new(1, 38));
    assert_eq!(info.negotiated_version, ProtocolVersion::new(1, 38));
    assert_eq!(info.daemon_nix_version.as_deref(), Some("2.33.3"));
    assert_eq!(info.trust_status, Some(1)); // trusted
}

#[tokio::test]
async fn decode_all_ops_from_recording() {
    let records = load_fixture("simple_session.nixwire");
    let (client_bytes, daemon_bytes) = split_directions(&records);

    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));

    let info = protocol::parse_handshake(&mut client, &mut daemon)
        .await
        .unwrap();
    let version = info.negotiated_version;
    let uses_framed = version >= ProtocolVersion::new(1, 23);

    let mut ops = Vec::new();

    loop {
        let op_code = match client.peek_u64().await.unwrap() {
            Some(v) => v,
            None => break,
        };
        client.consume(8);

        let op = Op::from_u64(op_code);
        assert!(op.is_some(), "unknown op code: {op_code}");
        let op = op.unwrap();

        let arg_info = protocol::skip_op_args(op, version, &mut client)
            .await
            .unwrap();

        if uses_framed && protocol::op_has_client_framed_data(op) {
            client.skip_framed().await.unwrap();
        }

        let stderr_result = protocol::read_stderr_loop(&mut daemon).await.unwrap();
        assert!(
            stderr_result.terminal.is_some(),
            "op {} missing terminal stderr code",
            op.name(),
        );
        let terminal = stderr_result.terminal.unwrap();

        if terminal == StderrCode::Last {
            protocol::skip_daemon_result(op, version, &mut daemon)
                .await
                .unwrap();
        }

        ops.push((op, arg_info, terminal));
    }

    // Verify the expected ops from the simple_session.nixwire recording
    assert_eq!(ops.len(), 15);

    // First op should be SetOptions
    assert_eq!(ops[0].0, Op::SetOptions);
    assert_eq!(ops[0].2, StderrCode::Last);

    // Check specific op types
    assert_eq!(ops[1].0, Op::AddTempRoot);
    assert_eq!(ops[2].0, Op::IsValidPath);
    assert_eq!(ops[3].0, Op::AddTempRoot);
    assert_eq!(ops[4].0, Op::AddIndirectRoot);
    assert_eq!(ops[5].0, Op::IsValidPath);
    assert_eq!(ops[6].0, Op::AddTempRoot);
    assert_eq!(ops[7].0, Op::IsValidPath);
    assert_eq!(ops[8].0, Op::IsValidPath);
    assert_eq!(ops[9].0, Op::QueryPathInfo);
    assert_eq!(ops[10].0, Op::AddTempRoot);
    assert_eq!(ops[11].0, Op::SetOptions);
    assert_eq!(ops[12].0, Op::IsValidPath);
    assert_eq!(ops[13].0, Op::QueryMissing);
    assert_eq!(ops[14].0, Op::BuildPathsWithResults);

    // All should be STDERR_LAST (success)
    for (op, _, terminal) in &ops {
        assert_eq!(
            *terminal,
            StderrCode::Last,
            "expected STDERR_LAST for {}, got {:?}",
            op.name(),
            terminal,
        );
    }
}

#[tokio::test]
async fn daemon_only_handshake_matches_full_handshake() {
    let records = load_fixture("simple_session.nixwire");
    let (client_bytes, daemon_bytes) = split_directions(&records);

    // Parse full handshake
    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes.clone()));
    let full_info = protocol::parse_handshake(&mut client, &mut daemon)
        .await
        .unwrap();

    // Parse daemon-only handshake
    let mut daemon2 = AsyncWireReader::new(MemReader::new(daemon_bytes));
    let daemon_info = protocol::parse_daemon_handshake(
        &mut daemon2,
        full_info.client_version,
    )
    .await
    .unwrap();

    assert_eq!(daemon_info.server_version, full_info.server_version);
    assert_eq!(daemon_info.negotiated_version, full_info.negotiated_version);
    assert_eq!(daemon_info.daemon_nix_version, full_info.daemon_nix_version);
    assert_eq!(daemon_info.trust_status, full_info.trust_status);
    assert_eq!(daemon_info.server_features, full_info.server_features);
}

#[tokio::test]
async fn mem_reader_position_tracks_protocol_parsing() {
    let records = load_fixture("simple_session.nixwire");
    let (client_bytes, daemon_bytes) = split_directions(&records);

    let client_len = client_bytes.len();
    let daemon_len = daemon_bytes.len();

    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));

    // Before parsing, position is 0
    assert_eq!(client.inner_ref().position(), 0);
    assert_eq!(daemon.inner_ref().position(), 0);

    let info = protocol::parse_handshake(&mut client, &mut daemon)
        .await
        .unwrap();

    // After handshake, positions should have advanced
    assert!(client.inner_ref().position() > 0);
    assert!(daemon.inner_ref().position() > 0);

    let version = info.negotiated_version;
    let uses_framed = version >= ProtocolVersion::new(1, 23);

    // Parse all ops
    loop {
        let op_code = match client.peek_u64().await.unwrap() {
            Some(v) => v,
            None => break,
        };
        client.consume(8);

        let op = Op::from_u64(op_code).unwrap();
        let _ = protocol::skip_op_args(op, version, &mut client).await;
        if uses_framed && protocol::op_has_client_framed_data(op) {
            let _ = client.skip_framed().await;
        }

        let stderr = protocol::read_stderr_loop(&mut daemon).await.unwrap();
        if stderr.terminal == Some(StderrCode::Last) {
            let _ = protocol::skip_daemon_result(op, version, &mut daemon).await;
        }
    }

    // After parsing everything, positions should match total stream lengths
    assert_eq!(
        client.inner_ref().position(),
        client_len,
        "client stream not fully consumed",
    );
    assert_eq!(
        daemon.inner_ref().position(),
        daemon_len,
        "daemon stream not fully consumed",
    );
}

/// Synthetic handshake test: build wire bytes manually and verify parsing.
#[tokio::test]
async fn synthetic_handshake_v1_38_with_features() {
    use nix_wire::handshake::{WORKER_MAGIC_1, WORKER_MAGIC_2};

    let client_ver = ProtocolVersion::new(1, 38);
    let server_ver = ProtocolVersion::new(1, 38);

    let mut client_bytes = Vec::new();
    let mut daemon_bytes = Vec::new();

    // Client: magic + version
    client_bytes.extend_from_slice(&WORKER_MAGIC_1.to_le_bytes());
    client_bytes.extend_from_slice(&client_ver.to_wire().to_le_bytes());

    // Daemon: magic + version
    daemon_bytes.extend_from_slice(&WORKER_MAGIC_2.to_le_bytes());
    daemon_bytes.extend_from_slice(&server_ver.to_wire().to_le_bytes());

    // Client features: ["ca-derivations"]
    client_bytes.extend_from_slice(&1u64.to_le_bytes()); // count
    let feat = b"ca-derivations";
    client_bytes.extend_from_slice(&(feat.len() as u64).to_le_bytes());
    client_bytes.extend_from_slice(feat);
    client_bytes.extend_from_slice(&[0, 0]); // padding to 8

    // Daemon features: ["ca-derivations", "daemon-trust-override"]
    daemon_bytes.extend_from_slice(&2u64.to_le_bytes()); // count
    let feat1 = b"ca-derivations";
    daemon_bytes.extend_from_slice(&(feat1.len() as u64).to_le_bytes());
    daemon_bytes.extend_from_slice(feat1);
    daemon_bytes.extend_from_slice(&[0, 0]); // padding
    let feat2 = b"daemon-trust-override";
    daemon_bytes.extend_from_slice(&(feat2.len() as u64).to_le_bytes());
    daemon_bytes.extend_from_slice(feat2);
    daemon_bytes.extend_from_slice(&[0, 0, 0]); // padding to 8

    // CPU affinity (>= 1.14): flag=0
    client_bytes.extend_from_slice(&0u64.to_le_bytes());

    // reserveSpace (>= 1.11): value=0
    client_bytes.extend_from_slice(&0u64.to_le_bytes());

    // Daemon version string (>= 1.33)
    let ver = b"2.24.0";
    daemon_bytes.extend_from_slice(&(ver.len() as u64).to_le_bytes());
    daemon_bytes.extend_from_slice(ver);
    daemon_bytes.extend_from_slice(&[0, 0]); // padding

    // Trust (>= 1.35): trusted=1
    daemon_bytes.extend_from_slice(&1u64.to_le_bytes());

    // STDERR_LAST
    daemon_bytes.extend_from_slice(&(StderrCode::Last as u64).to_le_bytes());

    let mut client = AsyncWireReader::new(MemReader::new(client_bytes));
    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));

    let info = protocol::parse_handshake(&mut client, &mut daemon)
        .await
        .unwrap();

    assert_eq!(info.client_version, client_ver);
    assert_eq!(info.server_version, server_ver);
    assert_eq!(info.negotiated_version, ProtocolVersion::new(1, 38));
    assert_eq!(info.client_features, vec!["ca-derivations"]);
    assert_eq!(
        info.server_features,
        vec!["ca-derivations", "daemon-trust-override"],
    );
    assert_eq!(info.daemon_nix_version.as_deref(), Some("2.24.0"));
    assert_eq!(info.trust_status, Some(1));
}

/// Test that stderr loop correctly handles STDERR_ERROR
#[tokio::test]
async fn stderr_error_with_payload() {
    let mut daemon_bytes = Vec::new();

    // STDERR_NEXT with a log message
    daemon_bytes.extend_from_slice(&(StderrCode::Next as u64).to_le_bytes());
    let msg = b"building...";
    daemon_bytes.extend_from_slice(&(msg.len() as u64).to_le_bytes());
    daemon_bytes.extend_from_slice(msg);
    daemon_bytes.extend_from_slice(&[0, 0, 0, 0, 0]); // padding to 8

    // STDERR_ERROR
    daemon_bytes.extend_from_slice(&(StderrCode::Error as u64).to_le_bytes());

    let mut daemon = AsyncWireReader::new(MemReader::new(daemon_bytes));
    let result = protocol::read_stderr_loop(&mut daemon).await.unwrap();

    assert_eq!(result.count, 2); // NEXT + ERROR
    assert_eq!(result.terminal, Some(StderrCode::Error));
}
