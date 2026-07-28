use std::fs;
use std::io::{self, BufRead, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use gorce_provider_abi::{
    decode_request, decode_request_with_limits, encode_message, request_id_from_frame,
    CancelParams, HostLimits, InitializeParams, InitializeResult, JsonRpcRequest, JsonRpcResponse,
    RequestId, RuntimeCapabilities, SessionState, ShutdownParams, ToolDescriptor, ToolInvokeParams,
    ToolResult, VersionRange, MAX_FRAME_BYTES, METHOD_CANCEL, METHOD_INITIALIZE, METHOD_SHUTDOWN,
    METHOD_TOOL_INVOKE, PROVIDER_ABI_VERSION,
};
use serde_json::{json, Value};

use mock_web_search::{tool_id, CREDENTIAL_CLASS, PROVIDER_ID, SENTINEL_SECRET, TOOL_NAME};

fn main() -> io::Result<()> {
    let archive_path = std::env::var_os("GORCE_PROVIDER_ARCHIVE_PATH").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider archive path is required",
        )
    })?;
    let archive_bytes = fs::read(archive_path)?;
    let verified_archive = gorce_provider_abi::verify_provider_archive(&archive_bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let executable_bytes = fs::read(std::env::current_exe()?)?;
    if executable_bytes.as_slice() != verified_archive.executable_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launched executable is not the archive-authorized executable",
        ));
    }
    let verified_manifest = verified_archive.manifest().clone();
    let archive_digest = verified_archive.package().archive_digest.clone();
    let mut state = SessionState::AwaitInitialize;
    let mut negotiated_limits: Option<HostLimits> = None;
    let mut pending: Option<PendingInvocation> = None;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let output = Arc::new(Mutex::new(io::BufWriter::new(io::stdout())));
    while let Some(frame) = read_bounded_frame(&mut input)? {
        if pending
            .as_ref()
            .is_some_and(|operation| operation.completed.load(Ordering::Acquire))
        {
            let operation = pending.take().expect("completed operation");
            let _ = operation.handle.join();
        }
        let request = if let Some(limits) = &negotiated_limits {
            decode_request_with_limits(&frame, limits)
        } else {
            decode_request(&frame)
        };
        let response = match request {
            Ok(request) => {
                let method = request.method.clone();
                let request_id = request.id.clone();
                if let Err(error) = state.validate_request(&request) {
                    JsonRpcResponse::failure(request_id, -32020, error.to_string())
                } else if method == METHOD_CANCEL && pending.is_some() {
                    let cancel = request.typed_params::<CancelParams>();
                    if let Ok(cancel) = cancel {
                        if pending.as_ref().is_some_and(|operation| {
                            operation.invocation_id == cancel.invocation_id
                        }) {
                            let operation = pending.as_ref().expect("pending operation");
                            operation.cancel.store(true, Ordering::Release);
                            let operation = pending.take().expect("pending operation");
                            let _ = operation.handle.join();
                            JsonRpcResponse::success(
                                request.id,
                                &json!({
                                    "cancelled": true,
                                    "invocation_id": cancel.invocation_id
                                }),
                            )
                            .expect("bounded cancellation response")
                        } else {
                            JsonRpcResponse::failure(
                                request.id,
                                -32012,
                                "cancellation does not match the active invocation",
                            )
                        }
                    } else {
                        JsonRpcResponse::failure(request_id, -32602, "invalid cancellation params")
                    }
                } else if pending.is_some() {
                    JsonRpcResponse::failure(request_id, -32011, "provider operation is busy")
                } else if method == METHOD_CANCEL {
                    JsonRpcResponse::failure(request_id, -32012, "no active invocation")
                } else if method == METHOD_TOOL_INVOKE
                    && request
                        .typed_params::<ToolInvokeParams>()
                        .ok()
                        .and_then(|params| {
                            params
                                .input
                                .get("query")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .is_some_and(|query| matches!(query.as_str(), "pending" | "abnormal"))
                {
                    let params = request
                        .typed_params::<ToolInvokeParams>()
                        .expect("validated invocation params");
                    if let Err(error) = params.validate_for(&verified_manifest, &archive_digest) {
                        JsonRpcResponse::failure(request_id, -32002, error.to_string())
                    } else {
                        pending = Some(start_pending(
                            request.id,
                            params,
                            verified_manifest.clone(),
                            archive_digest.to_owned(),
                            Arc::clone(&output),
                            negotiated_limits
                                .clone()
                                .expect("initialized provider has negotiated limits"),
                        ));
                        continue;
                    }
                } else {
                    let initial_limits = if method == METHOD_INITIALIZE {
                        request
                            .typed_params::<InitializeParams>()
                            .ok()
                            .map(|params| params.limits)
                    } else {
                        None
                    };
                    let response =
                        dispatch(&mut state, request, &verified_manifest, &archive_digest);
                    if response.error.is_none() && method == METHOD_INITIALIZE {
                        negotiated_limits = initial_limits;
                    }
                    response
                }
            }
            Err(error) => {
                let Some(id) = request_id_from_frame(&frame) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    ));
                };
                let code = if matches!(&error, gorce_provider_abi::RpcCodecError::InvalidParams(_))
                {
                    -32602
                } else {
                    -32700
                };
                JsonRpcResponse::failure(id, code, error.to_string())
            }
        };
        let is_shutdown = response
            .result
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|value| value.get("shutdown"))
            .and_then(Value::as_bool)
            == Some(true);
        write_response(&output, &response, negotiated_limits.as_ref())?;
        if is_shutdown {
            break;
        }
    }
    if let Some(operation) = pending.take() {
        operation.cancel.store(true, Ordering::Release);
        let _ = operation.handle.join();
    }
    Ok(())
}

fn dispatch(
    state: &mut SessionState,
    request: JsonRpcRequest,
    manifest: &gorce_provider_abi::Manifest,
    archive_digest: &str,
) -> JsonRpcResponse {
    let id = request.id.clone();
    let method = request.method.clone();
    let result = match method.as_str() {
        METHOD_INITIALIZE => initialize(
            request.typed_params::<InitializeParams>(),
            id,
            manifest,
            archive_digest,
        ),
        METHOD_TOOL_INVOKE => invoke(
            request.typed_params::<ToolInvokeParams>(),
            id,
            manifest,
            archive_digest,
        ),
        METHOD_CANCEL => cancel(request.typed_params::<CancelParams>(), id),
        METHOD_SHUTDOWN => shutdown(request.typed_params::<ShutdownParams>(), id),
        _ => Ok(JsonRpcResponse::failure(id, -32601, "method not found")),
    };
    let response = result.unwrap_or_else(|error| {
        JsonRpcResponse::failure(
            RequestId::new("internal").expect("fixture request ID"),
            -32602,
            error.to_string(),
        )
    });
    if response.error.is_none() {
        if method == METHOD_INITIALIZE {
            state.initialized();
        } else if method == METHOD_SHUTDOWN {
            state.shutting_down();
        }
    }
    response
}

struct PendingInvocation {
    invocation_id: String,
    cancel: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

type SharedOutput = Arc<Mutex<io::BufWriter<io::Stdout>>>;

fn start_pending(
    request_id: RequestId,
    params: ToolInvokeParams,
    manifest: gorce_provider_abi::Manifest,
    archive_digest: String,
    output: SharedOutput,
    negotiated_limits: HostLimits,
) -> PendingInvocation {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let completed = Arc::new(AtomicBool::new(false));
    let worker_completed = Arc::clone(&completed);
    let invocation_id = params.invocation.invocation_id.clone();
    let worker_invocation_id = invocation_id.clone();
    let handle = thread::spawn(move || {
        let query = params
            .input
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let started_at = now_unix_ms();
        let terminal = loop {
            if worker_cancel.load(Ordering::Acquire) {
                break JsonRpcResponse::failure(
                    request_id.clone(),
                    -32012,
                    "active invocation cancelled",
                );
            }
            if now_unix_ms() >= params.invocation.deadline_unix_ms {
                break JsonRpcResponse::failure(
                    request_id.clone(),
                    -32010,
                    "invocation deadline exceeded",
                );
            }
            if query == "abnormal" {
                // Keep this invocation active briefly before terminating the
                // provider. The conformance test must observe a real process
                // failure, not a synthesized JSON-RPC error response.
                thread::sleep(Duration::from_millis(25));
                std::process::exit(101);
            }
            if query != "pending" || now_unix_ms() >= started_at.saturating_add(1_000) {
                let result = build_tool_result(&params, &manifest, &archive_digest);
                break match result {
                    Ok(result) => JsonRpcResponse::success(request_id.clone(), &result)
                        .expect("bounded natural completion response"),
                    Err(error) => JsonRpcResponse::failure(request_id.clone(), -32002, error),
                };
            }
            thread::sleep(Duration::from_millis(10));
        };
        let _ = write_response(&output, &terminal, Some(&negotiated_limits));
        worker_completed.store(true, Ordering::Release);
    });
    PendingInvocation {
        invocation_id: worker_invocation_id,
        cancel,
        completed,
        handle,
    }
}

fn write_response(
    output: &SharedOutput,
    response: &JsonRpcResponse,
    negotiated_limits: Option<&HostLimits>,
) -> io::Result<()> {
    let frame = match negotiated_limits {
        Some(limits) => response.encode_with_limits(limits),
        None => response.validate().and_then(|_| encode_message(response)),
    }
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let mut output = output
        .lock()
        .map_err(|_| io::Error::other("provider output lock poisoned"))?;
    output.write_all(&frame)?;
    output.flush()
}

fn read_bounded_frame(input: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Ok(Some(frame))
            };
        }
        let until_lf = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        if oversized {
            let has_line_feed = buffer[..until_lf].last() == Some(&b'\n');
            input.consume(until_lf);
            if has_line_feed {
                return Ok(Some(frame));
            }
            continue;
        }
        let room = MAX_FRAME_BYTES + 1 - frame.len();
        let take = until_lf.min(room);
        frame.extend_from_slice(&buffer[..take]);
        input.consume(take);
        if frame.last() == Some(&b'\n') {
            return Ok(Some(frame));
        }
        if frame.len() > MAX_FRAME_BYTES {
            oversized = true;
        }
    }
}

fn initialize(
    params: Result<InitializeParams, gorce_provider_abi::RpcCodecError>,
    id: RequestId,
    manifest: &gorce_provider_abi::Manifest,
    archive_digest: &str,
) -> Result<JsonRpcResponse, gorce_provider_abi::RpcCodecError> {
    let params = params?;
    if params.version_range.minimum != PROVIDER_ABI_VERSION
        || params.version_range.maximum != PROVIDER_ABI_VERSION
    {
        return Ok(JsonRpcResponse::failure(
            id,
            -32001,
            "unsupported provider ABI version range",
        ));
    }
    let result = InitializeResult {
        abi_version: PROVIDER_ABI_VERSION.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        package_digest: archive_digest.to_owned(),
        tools: manifest
            .tools
            .iter()
            .map(|tool| ToolDescriptor::from_manifest(manifest, archive_digest, tool))
            .collect(),
        capabilities: RuntimeCapabilities::from_manifest(manifest, archive_digest),
    };
    result
        .validate_for(manifest, archive_digest)
        .expect("fixture metadata matches manifest");
    JsonRpcResponse::success(id, &result)
}

fn invoke(
    params: Result<ToolInvokeParams, gorce_provider_abi::RpcCodecError>,
    id: RequestId,
    manifest: &gorce_provider_abi::Manifest,
    archive_digest: &str,
) -> Result<JsonRpcResponse, gorce_provider_abi::RpcCodecError> {
    let params = params?;
    if params.invocation.deadline_unix_ms <= now_unix_ms() {
        return Ok(JsonRpcResponse::failure(
            id,
            -32010,
            "invocation deadline exceeded",
        ));
    }
    if let Err(error) = params.validate_for(manifest, archive_digest) {
        return Ok(JsonRpcResponse::failure(id, -32002, error.to_string()));
    }
    let result = build_tool_result(&params, manifest, archive_digest)
        .map_err(gorce_provider_abi::RpcCodecError::InvalidParams)?;
    JsonRpcResponse::success(id, &result)
}

fn build_tool_result(
    params: &ToolInvokeParams,
    manifest: &gorce_provider_abi::Manifest,
    archive_digest: &str,
) -> Result<ToolResult, String> {
    let query = params
        .input
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let max_results = params
        .input
        .get("max_results")
        .and_then(Value::as_u64)
        .unwrap_or(3)
        .min(5);
    let output = json!({
        "query": query,
        "results": (0..max_results).map(|index| json!({
            "title": format!("{query} result {index}"),
            "url": format!("https://mock.invalid/{index}"),
            "snippet": format!("deterministic result for {query}")
        })).collect::<Vec<_>>()
    });
    let result = ToolResult {
        invocation_id: params.invocation.invocation_id.clone(),
        output,
    };
    result
        .validate_for(
            manifest,
            archive_digest,
            TOOL_NAME,
            &params.invocation.invocation_id,
        )
        .map_err(|error| error.to_string())?;
    if serde_json::to_string(&result)
        .map_err(|error| error.to_string())?
        .contains(SENTINEL_SECRET)
    {
        return Err("fixture output contains a secret sentinel".to_owned());
    }
    Ok(result)
}

fn cancel(
    params: Result<CancelParams, gorce_provider_abi::RpcCodecError>,
    id: RequestId,
) -> Result<JsonRpcResponse, gorce_provider_abi::RpcCodecError> {
    let _ = params?;
    JsonRpcResponse::success(id, &json!({"cancelled": true}))
}

fn shutdown(
    params: Result<ShutdownParams, gorce_provider_abi::RpcCodecError>,
    id: RequestId,
) -> Result<JsonRpcResponse, gorce_provider_abi::RpcCodecError> {
    let _ = params?;
    JsonRpcResponse::success(id, &json!({"shutdown": true}))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

#[allow(dead_code)]
fn _fixture_initialize() -> InitializeParams {
    InitializeParams {
        version_range: VersionRange {
            minimum: PROVIDER_ABI_VERSION.to_owned(),
            maximum: PROVIDER_ABI_VERSION.to_owned(),
        },
        limits: HostLimits {
            max_frame_bytes: gorce_provider_abi::MAX_FRAME_BYTES as u32,
            max_json_depth: gorce_provider_abi::MAX_JSON_DEPTH as u16,
            max_members: gorce_provider_abi::MAX_JSON_MEMBERS as u16,
            max_timeout_ms: gorce_provider_abi::MAX_TIMEOUT_MS as u32,
        },
    }
}

#[allow(dead_code)]
fn _fixture_tool_id() -> String {
    let _ = CREDENTIAL_CLASS;
    tool_id()
}

fn _secret_is_not_in_public_result() {
    let _ = SENTINEL_SECRET;
}
