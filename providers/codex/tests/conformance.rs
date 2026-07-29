use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use codex::{
    archive_bytes_for_executable, AUTH_METHOD_ID, CREDENTIAL_CLASS, PROVIDER_ID, SENTINEL_SECRET,
    TOOL_WEB_SEARCH,
};
use gorce_provider_abi::{
    decode_frame_with_limits, decode_response_with_limits, encode_message, AuthorizedInvocation,
    DeliveryKind, HostLimits, InitializeParams, InitializeResult, JsonRpcRequest, RequestId,
    ScopedSecretDelivery, ToolInvokeParams, VersionRange, METHOD_CANCEL, METHOD_INITIALIZE,
    METHOD_SHUTDOWN, METHOD_TOOL_INVOKE,
};
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
            max_frame_bytes: 8192,
            max_json_depth: 12,
            max_members: 192,
            max_timeout_ms: 30_000,
        },
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn invoke_params(archive_digest: &str, id: &str, input: Value) -> ToolInvokeParams {
    let deadline_unix_ms = now_unix_ms() + 30_000;
    ToolInvokeParams {
        invocation: AuthorizedInvocation {
            package_digest: archive_digest.to_owned(),
            tool_id: gorce_provider_abi::derive_tool_id(
                archive_digest,
                PROVIDER_ID,
                TOOL_WEB_SEARCH,
            ),
            invocation_id: id.to_owned(),
            auth_method_id: Some(AUTH_METHOD_ID.to_owned()),
            credential_class: Some(CREDENTIAL_CLASS.to_owned()),
            delivery_kind: Some(DeliveryKind::AccessToken),
            deadline_unix_ms,
        },
        input,
        secret_delivery: Some(ScopedSecretDelivery {
            kind: DeliveryKind::AccessToken,
            credential_class: CREDENTIAL_CLASS.to_owned(),
            value: SENTINEL_SECRET.to_owned(),
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
    assert!(!line.is_empty(), "provider exited before replying");
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

#[test]
fn spawned_package_conforms_to_canonical_v1_and_redacts_secret_from_results() {
    let executable = env!("CARGO_BIN_EXE_codex");
    let executable_bytes = fs::read(executable).unwrap();
    let archive_bytes = archive_bytes_for_executable(&executable_bytes);
    let verified = gorce_provider_abi::verify_provider_archive(&archive_bytes).unwrap();
    assert_eq!(verified.executable_bytes(), executable_bytes);
    assert_eq!(verified.manifest().provider_id, PROVIDER_ID);
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

    let premature = round_trip(
        &mut reader,
        &mut writer,
        &request(
            "req-0",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(invoke_params(
                &package_digest,
                "inv-0",
                json!({"query": "gorce"}),
            ))
            .unwrap(),
        ),
    );
    assert_eq!(premature["error"]["code"], -32020);

    let initialized = round_trip(
        &mut reader,
        &mut writer,
        &request(
            "req-1",
            METHOD_INITIALIZE,
            serde_json::to_value(initialize_params()).unwrap(),
        ),
    );
    let initialize_result: InitializeResult =
        serde_json::from_value(initialized["result"].clone()).unwrap();
    initialize_result
        .validate_for(verified.manifest(), &package_digest)
        .unwrap();
    assert_eq!(initialize_result.tools.len(), 1);

    let searched = round_trip(
        &mut reader,
        &mut writer,
        &request(
            "req-2",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(invoke_params(
                &package_digest,
                "inv-search",
                json!({"query": "gorce", "max_results": 3}),
            ))
            .unwrap(),
        ),
    );
    assert_eq!(searched["result"]["invocation_id"], "inv-search");
    assert_eq!(
        searched["result"]["output"]["results"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(!searched.to_string().contains(SENTINEL_SECRET));

    let mut missing_delivery = invoke_params(
        &package_digest,
        "inv-missing-delivery",
        json!({"query": "x"}),
    );
    missing_delivery.secret_delivery = None;
    let missing_delivery = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-3",
            METHOD_TOOL_INVOKE,
            serde_json::to_value(missing_delivery).unwrap(),
        ))
        .unwrap(),
    );
    assert_eq!(missing_delivery["error"]["code"], -32002);

    let cancelled = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request(
            "req-4",
            METHOD_CANCEL,
            json!({"invocation_id": "inv-search"}),
        ))
        .unwrap(),
    );
    assert_eq!(cancelled["error"]["code"], -32012);

    let shutdown = raw_round_trip(
        &mut reader,
        &mut writer,
        &encode_message(&request("req-5", METHOD_SHUTDOWN, json!({}))).unwrap(),
    );
    assert_eq!(shutdown["result"]["shutdown"], true);
    drop(writer);
    assert!(child.wait().unwrap().success());
    fs::remove_file(extracted).unwrap();
    fs::remove_file(archive_path).unwrap();
}

#[test]
fn manifest_is_valid_and_carries_ported_oauth_surface() {
    let manifest = codex::manifest_for_executable(b"fixture-executable");
    manifest.validate().unwrap();
    let auth = manifest.auth_method(AUTH_METHOD_ID).unwrap();
    assert_eq!(auth.credential_class(), CREDENTIAL_CLASS);
    assert_eq!(
        auth.scopes(),
        ["openid", "profile", "email", "offline_access"]
    );
    assert_eq!(manifest.tools.len(), 1, "upstream has no native web fetch");
    let search = manifest.tool(TOOL_WEB_SEARCH).unwrap();
    assert_eq!(search.network_origins, [codex::API_ORIGIN]);
}
