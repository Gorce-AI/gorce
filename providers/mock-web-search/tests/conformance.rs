use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gorce_provider_abi::{
    decode_frame, decode_frame_with_limits, decode_response_with_limits, encode_message,
    AuthorizedInvocation, DeliveryKind, HostLimits, InitializeParams, InitializeResult,
    JsonRpcRequest, JsonRpcResponse, RequestId, ScopedSecretDelivery, ToolInvokeParams, ToolResult,
    VersionRange, METHOD_CANCEL, METHOD_INITIALIZE, METHOD_SHUTDOWN, METHOD_TOOL_INVOKE,
};
use mock_web_search::{archive_bytes_for_executable, CREDENTIAL_CLASS, PROVIDER_ID};
use serde_json::{json, Value};

fn request(id: &str, method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: RequestId::new(id).unwrap(),
        method: method.to_owned(),
        params,
    }
}

fn initialize_params() -> InitializeParams {
    InitializeParams {
        version_range: VersionRange {
            minimum: gorce_provider_abi::PROVIDER_ABI_VERSION.to_owned(),
            maximum: gorce_provider_abi::PROVIDER_ABI_VERSION.to_owned(),
        },
        limits: HostLimits {
            max_frame_bytes: 4096,
            max_json_depth: 12,
            max_members: 128,
            max_timeout_ms: 30_000,
        },
    }
}

fn deadline() -> u64 {
    now_unix_ms() + 30_000
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn invocation(archive_digest: &str, id: &str, deadline_unix_ms: u64) -> AuthorizedInvocation {
    AuthorizedInvocation {
        package_digest: archive_digest.to_owned(),
        tool_id: gorce_provider_abi::derive_tool_id(archive_digest, PROVIDER_ID, "web_search"),
        invocation_id: id.to_owned(),
        auth_method_id: Some("search_api_key".to_owned()),
        credential_class: Some(CREDENTIAL_CLASS.to_owned()),
        delivery_kind: Some(DeliveryKind::ApiKey),
        deadline_unix_ms,
    }
}

fn invoke_params(archive_digest: &str, id: &str, deadline_unix_ms: u64) -> ToolInvokeParams {
    ToolInvokeParams {
        invocation: invocation(archive_digest, id, deadline_unix_ms),
        input: json!({"query": "gorce", "max_results": 2}),
        secret_delivery: Some(ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: CREDENTIAL_CLASS.to_owned(),
            value: mock_web_search::SENTINEL_SECRET.to_owned(),
            expires_at_unix_ms: deadline_unix_ms,
        }),
    }
}

fn round_trip(
    reader: &mut BufReader<impl std::io::Read>,
    writer: &mut impl Write,
    request: &JsonRpcRequest,
) -> Value {
    writer.write_all(&encode_message(request).unwrap()).unwrap();
    writer.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "mock provider exited before replying");
    serde_json::to_value(
        decode_response_with_limits(line.as_bytes(), &initialize_params().limits).unwrap(),
    )
    .unwrap()
}

fn raw_round_trip(
    reader: &mut BufReader<impl std::io::Read>,
    writer: &mut impl Write,
    frame: &[u8],
) -> Value {
    writer.write_all(frame).unwrap();
    writer.flush().unwrap();
    read_value(reader)
}

fn read_value(reader: &mut BufReader<impl std::io::Read>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    decode_frame_with_limits(line.as_bytes(), &initialize_params().limits).unwrap()
}

fn spawn_provider(path: &std::path::Path, archive_path: &std::path::Path) -> Child {
    Command::new(path)
        .env("GORCE_PROVIDER_ARCHIVE_PATH", archive_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn reap_provider_with_timeout(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait().unwrap();
                panic!("mock provider did not exit within the test timeout: {status:?}");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[test]
fn spawned_package_conforms_to_canonical_v1_and_redacts_secret_from_results() {
    let executable = env!("CARGO_BIN_EXE_mock-web-search");
    let executable_bytes = fs::read(executable).unwrap();
    let archive_bytes = archive_bytes_for_executable(&executable_bytes);
    let verified = gorce_provider_abi::verify_provider_archive(&archive_bytes).unwrap();
    assert_eq!(verified.executable_bytes(), executable_bytes);
    let package_digest = verified.archive_digest().to_owned();
    let extracted = std::env::temp_dir().join(format!(
        "gorce-provider-{}-{}",
        std::process::id(),
        verified.archive_digest()
    ));
    let archive_path = extracted.with_extension("gorce-provider");
    fs::write(&archive_path, &archive_bytes).unwrap();
    fs::write(&extracted, verified.executable_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&extracted, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut child = spawn_provider(&extracted, &archive_path);
    let mut writer = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    assert_eq!(verified.manifest().provider_id, PROVIDER_ID);

    let first = round_trip(
        &mut reader,
        &mut writer,
        &request(
            "req-0",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(invoke_params(&package_digest, "inv-0", deadline())).unwrap(),
        ),
    );
    assert_eq!(first["error"]["code"], -32020);

    let initialized = round_trip(
        &mut reader,
        &mut writer,
        &request(
            "req-1",
            METHOD_INITIALIZE,
            serde_json::to_value(initialize_params()).unwrap(),
        ),
    );
    let malformed = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&json!({
            "jsonrpc": "2.0",
            "id": "req-malformed",
            "method": METHOD_TOOL_INVOKE,
            "params": {"input": {"query": "missing invocation"}}
        }))
        .unwrap(),
    );
    assert_eq!(malformed["id"], "req-malformed");
    assert_eq!(malformed["error"]["code"], -32602);
    let initialize_result: InitializeResult =
        serde_json::from_value(initialized["result"].clone()).unwrap();
    initialize_result
        .validate_for(verified.manifest(), &package_digest)
        .unwrap();
    let mut escalated = initialize_result.clone();
    escalated.tools[0].description.push_str(" escalation");
    assert!(escalated
        .validate_for(verified.manifest(), &package_digest)
        .is_err());

    let mut pending_params = invoke_params(&package_digest, "inv-pending", deadline());
    pending_params.input["query"] = json!("pending");
    writer
        .write_all(
            &encode_message(&request(
                "req-pending",
                METHOD_TOOL_INVOKE,
                serde_json::to_value(pending_params).unwrap(),
            ))
            .unwrap(),
        )
        .unwrap();
    writer.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(25));
    writer
        .write_all(
            &encode_message(&request(
                "req-cancel",
                METHOD_CANCEL,
                json!({"invocation_id": "inv-pending", "reason": "active cancellation"}),
            ))
            .unwrap(),
        )
        .unwrap();
    writer.flush().unwrap();
    let terminal = read_value(&mut reader);
    let cancel_response = read_value(&mut reader);
    assert_eq!(terminal["id"], "req-pending");
    assert_eq!(terminal["error"]["code"], -32012);
    assert_eq!(cancel_response["id"], "req-cancel");
    assert_eq!(cancel_response["result"]["cancelled"], true);

    let mut natural_params = invoke_params(&package_digest, "inv-natural", deadline());
    natural_params.input["query"] = json!("pending");
    writer
        .write_all(
            &encode_message(&request(
                "req-natural",
                METHOD_TOOL_INVOKE,
                serde_json::to_value(natural_params).unwrap(),
            ))
            .unwrap(),
        )
        .unwrap();
    writer.flush().unwrap();
    let natural = read_value(&mut reader);
    assert_eq!(natural["id"], "req-natural");
    assert_eq!(natural["result"]["invocation_id"], "inv-natural");
    std::thread::sleep(std::time::Duration::from_millis(25));

    let duplicate_init = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-2",
            METHOD_INITIALIZE,
            serde_json::to_value(initialize_params()).unwrap(),
        ))
        .unwrap(),
    );
    assert!(duplicate_init["error"]["message"]
        .as_str()
        .unwrap()
        .contains("once"));

    let invoked = round_trip(
        &mut reader,
        &mut writer,
        &request(
            "req-3",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(invoke_params(&package_digest, "inv-1", deadline())).unwrap(),
        ),
    );
    assert_eq!(invoked["result"]["invocation_id"], "inv-1");
    assert!(!invoked
        .to_string()
        .contains(mock_web_search::SENTINEL_SECRET));

    let expired = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-4",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(invoke_params(&package_digest, "inv-expired", 1)).unwrap(),
        ))
        .unwrap(),
    );
    assert_eq!(expired["error"]["code"], -32010);

    let forged = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request("req-5", METHOD_TOOL_INVOKE, json!({
            "invocation": {"package_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "tool_id": "gorce.provider/v1/tool/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/mock-web-search/web_search", "invocation_id": "inv-forged", "auth_method_id": CREDENTIAL_CLASS, "credential_class": CREDENTIAL_CLASS, "delivery_kind": "api_key", "deadline_unix_ms": deadline()},
            "input": {"query": "x"}, "secret_delivery": null
        }))).unwrap(),
    );
    assert_eq!(forged["error"]["code"], -32002);

    let mut missing_delivery = invoke_params(&package_digest, "inv-missing-delivery", deadline());
    missing_delivery.secret_delivery = None;
    let missing_delivery = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-missing-delivery",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(missing_delivery).unwrap(),
        ))
        .unwrap(),
    );
    assert_eq!(missing_delivery["error"]["code"], -32002);

    let mut mismatched_delivery =
        invoke_params(&package_digest, "inv-mismatched-delivery", deadline());
    mismatched_delivery.secret_delivery.as_mut().unwrap().kind = DeliveryKind::AccessToken;
    let mismatched_delivery = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-mismatched-delivery",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(mismatched_delivery).unwrap(),
        ))
        .unwrap(),
    );
    assert_eq!(mismatched_delivery["error"]["code"], -32602);

    let cancelled = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-6",
            METHOD_CANCEL,
            json!({"invocation_id": "inv-1"}),
        ))
        .unwrap(),
    );
    assert_eq!(cancelled["error"]["code"], -32012);

    let shutdown = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request("req-7", METHOD_SHUTDOWN, json!({}))).unwrap(),
    );
    assert_eq!(shutdown["result"]["shutdown"], true);
    drop(writer);
    assert!(child.wait().unwrap().success());

    let mut timeout_child = spawn_provider(&extracted, &archive_path);
    let mut timeout_writer = timeout_child.stdin.take().unwrap();
    let mut timeout_reader = BufReader::new(timeout_child.stdout.take().unwrap());
    timeout_writer
        .write_all(
            &encode_message(&request(
                "timeout-init",
                METHOD_INITIALIZE,
                serde_json::to_value(initialize_params()).unwrap(),
            ))
            .unwrap(),
        )
        .unwrap();
    timeout_writer.flush().unwrap();
    let mut init_line = String::new();
    timeout_reader.read_line(&mut init_line).unwrap();
    decode_response_with_limits(init_line.as_bytes(), &initialize_params().limits).unwrap();
    let mut timeout_params = invoke_params(&package_digest, "timeout-op", deadline());
    timeout_params.input["query"] = json!("pending");
    timeout_params.invocation.deadline_unix_ms = now_unix_ms() + 80;
    timeout_params
        .secret_delivery
        .as_mut()
        .unwrap()
        .expires_at_unix_ms = timeout_params.invocation.deadline_unix_ms;
    timeout_writer
        .write_all(
            &encode_message(&request(
                "timeout-op",
                METHOD_TOOL_INVOKE,
                serde_json::to_value(timeout_params).unwrap(),
            ))
            .unwrap(),
        )
        .unwrap();
    timeout_writer.flush().unwrap();
    let timeout_result = read_value(&mut timeout_reader);
    assert_eq!(timeout_result["id"], "timeout-op");
    assert_eq!(timeout_result["error"]["code"], -32010);
    std::thread::sleep(std::time::Duration::from_millis(25));
    let after_timeout = round_trip(
        &mut timeout_reader,
        &mut timeout_writer,
        &request(
            "timeout-after",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(invoke_params(&package_digest, "timeout-after", deadline()))
                .unwrap(),
        ),
    );
    assert_eq!(after_timeout["result"]["invocation_id"], "timeout-after");
    let timeout_shutdown = round_trip(
        &mut timeout_reader,
        &mut timeout_writer,
        &request("timeout-shutdown", METHOD_SHUTDOWN, json!({})),
    );
    assert_eq!(timeout_shutdown["result"]["shutdown"], true);
    drop(timeout_writer);
    assert!(timeout_child.wait().unwrap().success());

    let mut abnormal_child = spawn_provider(&extracted, &archive_path);
    let mut abnormal_writer = abnormal_child.stdin.take().unwrap();
    let mut abnormal_reader = BufReader::new(abnormal_child.stdout.take().unwrap());
    let mut abnormal_stderr = abnormal_child.stderr.take().unwrap();
    let abnormal_initialized = round_trip(
        &mut abnormal_reader,
        &mut abnormal_writer,
        &request(
            "abnormal-init",
            METHOD_INITIALIZE,
            serde_json::to_value(initialize_params()).unwrap(),
        ),
    );
    assert!(abnormal_initialized["result"].is_object());
    let mut abnormal_params = invoke_params(&package_digest, "abnormal-op", deadline());
    abnormal_params.input["query"] = json!("abnormal");
    abnormal_writer
        .write_all(
            &encode_message(&request(
                "abnormal-op",
                METHOD_TOOL_INVOKE,
                serde_json::to_value(abnormal_params).unwrap(),
            ))
            .unwrap(),
        )
        .unwrap();
    abnormal_writer.flush().unwrap();
    let abnormal_status = reap_provider_with_timeout(&mut abnormal_child);
    assert!(
        !abnormal_status.success(),
        "abnormal operation exited successfully"
    );
    assert_eq!(abnormal_status.code(), Some(101));
    drop(abnormal_writer);
    let mut abnormal_stdout = Vec::new();
    abnormal_reader.read_to_end(&mut abnormal_stdout).unwrap();
    assert!(
        abnormal_stdout.is_empty(),
        "abnormal operation unexpectedly returned a JSON-RPC response"
    );
    let mut abnormal_stderr_text = String::new();
    abnormal_stderr
        .read_to_string(&mut abnormal_stderr_text)
        .unwrap();
    assert!(!abnormal_stderr_text.contains(mock_web_search::SENTINEL_SECRET));

    let mut bounded_child = spawn_provider(&extracted, &archive_path);
    let mut bounded_writer = bounded_child.stdin.take().unwrap();
    let mut bounded_reader = BufReader::new(bounded_child.stdout.take().unwrap());
    bounded_writer
        .write_all(&vec![b'x'; gorce_provider_abi::MAX_FRAME_BYTES + 10])
        .unwrap();
    bounded_writer.write_all(b"\n").unwrap();
    bounded_writer.flush().unwrap();
    let mut bounded_line = String::new();
    bounded_reader.read_line(&mut bounded_line).unwrap();
    assert!(bounded_line.is_empty());
    bounded_child.kill().unwrap();
    assert!(!bounded_child.wait().unwrap().success());
    fs::remove_file(extracted).unwrap();
    fs::remove_file(archive_path).unwrap();
}

#[test]
fn malformed_frames_limits_and_secret_debug_are_rejected() {
    assert!(decode_frame(b"{}\r\n").is_err());
    assert!(decode_frame(b"{}").is_err());
    assert!(decode_frame(&vec![b'a'; gorce_provider_abi::MAX_FRAME_BYTES + 1]).is_err());
    assert!(RequestId::new("x".repeat(gorce_provider_abi::MAX_REQUEST_ID_BYTES + 1)).is_err());
    let mut limits = initialize_params();
    limits.limits.max_frame_bytes = (gorce_provider_abi::MAX_FRAME_BYTES as u32) + 1;
    assert!(serde_json::to_value(&limits)
        .ok()
        .map(|params| JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: RequestId::new("limit-test").unwrap(),
            method: METHOD_INITIALIZE.to_owned(),
            params,
        })
        .and_then(|request| request.validate().ok())
        .is_none());
    assert!(format!(
        "{:?}",
        ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: CREDENTIAL_CLASS.to_owned(),
            value: mock_web_search::SENTINEL_SECRET.to_owned(),
            expires_at_unix_ms: deadline(),
        }
    )
    .contains("<redacted>"));
    assert!(!format!(
        "{:?}",
        ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: CREDENTIAL_CLASS.to_owned(),
            value: mock_web_search::SENTINEL_SECRET.to_owned(),
            expires_at_unix_ms: deadline(),
        }
    )
    .contains(mock_web_search::SENTINEL_SECRET));
    let raw_request = request(
        "debug-request",
        METHOD_TOOL_INVOKE,
        serde_json::to_value(invoke_params("a".repeat(64).as_str(), "debug", deadline())).unwrap(),
    );
    assert!(!format!("{:?}", raw_request).contains(mock_web_search::SENTINEL_SECRET));
    let raw_response = JsonRpcResponse::success(
        RequestId::new("debug-response").unwrap(),
        &ToolResult {
            invocation_id: "debug".to_owned(),
            output: json!({"secret": mock_web_search::SENTINEL_SECRET}),
        },
    )
    .unwrap();
    assert!(!format!("{:?}", raw_response).contains(mock_web_search::SENTINEL_SECRET));
}
