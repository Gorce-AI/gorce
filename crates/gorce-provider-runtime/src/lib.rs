#![forbid(unsafe_code)]
//! Shared `gorce.provider/v1` session runtime for provider binaries.
//!
//! A provider package is an independently spawned executable speaking LF-NDJSON
//! JSON-RPC over stdin/stdout. This crate owns the protocol machinery — archive
//! and self-executable verification, bounded frame IO, session-state dispatch,
//! and secret redaction — so each provider binary only supplies its manifest and
//! a synchronous tool handler.

pub mod packaging;

use std::fs;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use gorce_provider_abi::{
    decode_request, decode_request_with_limits, encode_message, request_id_from_frame,
    CancelParams, HostLimits, InitializeParams, InitializeResult, JsonRpcRequest, JsonRpcResponse,
    Manifest, RequestId, RpcCodecError, RuntimeCapabilities, SessionState, ShutdownParams,
    ToolDescriptor, ToolInvokeParams, ToolResult, VersionRange, MAX_FRAME_BYTES, METHOD_INITIALIZE,
    METHOD_SHUTDOWN, METHOD_TOOL_INVOKE, PROVIDER_ABI_VERSION,
};
use serde_json::{json, Value};

/// Environment variable naming the `.gorce-provider` archive that authorizes
/// the launched executable.
pub const ARCHIVE_PATH_ENV: &str = "GORCE_PROVIDER_ARCHIVE_PATH";

/// The archive-backed identity of the running provider process.
pub struct VerifiedSelfPackage {
    manifest: Manifest,
    archive_digest: String,
}

impl VerifiedSelfPackage {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn archive_digest(&self) -> &str {
        &self.archive_digest
    }
}

/// A synchronous tool implementation. The runtime has already validated the
/// invocation against the manifest before the handler runs; the handler only
/// maps validated input to output for the named tool.
pub trait ToolHandler {
    fn invoke(&self, tool_name: &str, params: &ToolInvokeParams) -> Result<Value, String>;
}

impl<F> ToolHandler for F
where
    F: Fn(&str, &ToolInvokeParams) -> Result<Value, String>,
{
    fn invoke(&self, tool_name: &str, params: &ToolInvokeParams) -> Result<Value, String> {
        self(tool_name, params)
    }
}

/// Read the archive named by [`ARCHIVE_PATH_ENV`], verify it, and prove the
/// currently running executable is the archive-authorized one.
pub fn load_self_verified_package() -> io::Result<VerifiedSelfPackage> {
    let archive_path = std::env::var_os(ARCHIVE_PATH_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider archive path is required",
        )
    })?;
    let archive_bytes = fs::read(archive_path)?;
    let verified = gorce_provider_abi::verify_provider_archive(&archive_bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let executable_bytes = fs::read(std::env::current_exe()?)?;
    if executable_bytes.as_slice() != verified.executable_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launched executable is not the archive-authorized executable",
        ));
    }
    Ok(VerifiedSelfPackage {
        manifest: verified.manifest().clone(),
        archive_digest: verified.archive_digest().to_owned(),
    })
}

/// Run the JSON-RPC session on stdin/stdout until shutdown or EOF.
pub fn serve(package: &VerifiedSelfPackage, handler: &dyn ToolHandler) -> io::Result<()> {
    let mut state = SessionState::AwaitInitialize;
    let mut negotiated_limits: Option<HostLimits> = None;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::BufWriter::new(io::stdout());
    while let Some(frame) = read_bounded_frame(&mut input)? {
        let request = if let Some(limits) = &negotiated_limits {
            decode_request_with_limits(&frame, limits)
        } else {
            decode_request(&frame)
        };
        let response = match request {
            Ok(request) => {
                let method = request.method.clone();
                if let Err(error) = state.validate_request(&request) {
                    JsonRpcResponse::failure(request.id, -32020, error.to_string())
                } else {
                    let initial_limits = if method == METHOD_INITIALIZE {
                        request
                            .typed_params::<InitializeParams>()
                            .ok()
                            .map(|params| params.limits)
                    } else {
                        None
                    };
                    let response = dispatch(&mut state, request, package, handler);
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
                let code = if matches!(&error, RpcCodecError::InvalidParams(_)) {
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
        write_response(&mut output, &response, negotiated_limits.as_ref())?;
        if is_shutdown {
            break;
        }
    }
    Ok(())
}

fn dispatch(
    state: &mut SessionState,
    request: JsonRpcRequest,
    package: &VerifiedSelfPackage,
    handler: &dyn ToolHandler,
) -> JsonRpcResponse {
    let id = request.id.clone();
    let method = request.method.clone();
    let result = match method.as_str() {
        METHOD_INITIALIZE => initialize(request.typed_params::<InitializeParams>(), id, package),
        METHOD_TOOL_INVOKE => invoke(
            request.typed_params::<ToolInvokeParams>(),
            id,
            package,
            handler,
        ),
        gorce_provider_abi::METHOD_CANCEL => cancel(request.typed_params::<CancelParams>(), id),
        METHOD_SHUTDOWN => shutdown(request.typed_params::<ShutdownParams>(), id),
        _ => Ok(JsonRpcResponse::failure(id, -32601, "method not found")),
    };
    let response = result.unwrap_or_else(|error| {
        JsonRpcResponse::failure(
            RequestId::new("internal").expect("static request ID is bounded"),
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

fn initialize(
    params: Result<InitializeParams, RpcCodecError>,
    id: RequestId,
    package: &VerifiedSelfPackage,
) -> Result<JsonRpcResponse, RpcCodecError> {
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
    let manifest = package.manifest();
    let archive_digest = package.archive_digest();
    let result = InitializeResult {
        abi_version: PROVIDER_ABI_VERSION.to_owned(),
        provider_id: manifest.provider_id.clone(),
        package_digest: archive_digest.to_owned(),
        tools: manifest
            .tools
            .iter()
            .map(|tool| ToolDescriptor::from_manifest(manifest, archive_digest, tool))
            .collect(),
        capabilities: RuntimeCapabilities::from_manifest(manifest, archive_digest),
    };
    if let Err(error) = result.validate_for(manifest, archive_digest) {
        return Ok(JsonRpcResponse::failure(id, -32603, error.to_string()));
    }
    JsonRpcResponse::success(id, &result)
}

fn invoke(
    params: Result<ToolInvokeParams, RpcCodecError>,
    id: RequestId,
    package: &VerifiedSelfPackage,
    handler: &dyn ToolHandler,
) -> Result<JsonRpcResponse, RpcCodecError> {
    let params = params?;
    if params.invocation.deadline_unix_ms <= now_unix_ms() {
        return Ok(JsonRpcResponse::failure(
            id,
            -32010,
            "invocation deadline exceeded",
        ));
    }
    let manifest = package.manifest();
    let archive_digest = package.archive_digest();
    if let Err(error) = params.validate_for(manifest, archive_digest) {
        return Ok(JsonRpcResponse::failure(id, -32002, error.to_string()));
    }
    let tool_name = params
        .invocation
        .tool_id
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_owned();
    let output = match handler.invoke(&tool_name, &params) {
        Ok(output) => output,
        Err(error) => return Ok(JsonRpcResponse::failure(id, -32002, error)),
    };
    let result = ToolResult {
        invocation_id: params.invocation.invocation_id.clone(),
        output,
    };
    if let Err(error) = result.validate_for(
        manifest,
        archive_digest,
        &tool_name,
        &params.invocation.invocation_id,
    ) {
        return Ok(JsonRpcResponse::failure(id, -32002, error.to_string()));
    }
    if let Some(delivery) = &params.secret_delivery {
        let serialized = serde_json::to_string(&result)
            .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))?;
        if serialized.contains(&delivery.value) {
            return Ok(JsonRpcResponse::failure(
                id,
                -32002,
                "tool output contains the delivered secret",
            ));
        }
    }
    JsonRpcResponse::success(id, &result)
}

fn cancel(
    params: Result<CancelParams, RpcCodecError>,
    id: RequestId,
) -> Result<JsonRpcResponse, RpcCodecError> {
    let _ = params?;
    // Tool invocations complete synchronously before the next frame is read,
    // so a cancellation can never name an in-flight invocation.
    Ok(JsonRpcResponse::failure(id, -32012, "no active invocation"))
}

fn shutdown(
    params: Result<ShutdownParams, RpcCodecError>,
    id: RequestId,
) -> Result<JsonRpcResponse, RpcCodecError> {
    let _ = params?;
    JsonRpcResponse::success(id, &json!({"shutdown": true}))
}

fn write_response(
    output: &mut impl Write,
    response: &JsonRpcResponse,
    negotiated_limits: Option<&HostLimits>,
) -> io::Result<()> {
    let frame = match negotiated_limits {
        Some(limits) => response.encode_with_limits(limits),
        None => response.validate().and_then(|_| encode_message(response)),
    }
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

/// A canonical host-side `initialize` parameter set at the protocol's own
/// limits. Provider tests use it as the negotiated-limit fixture.
pub fn full_host_limits() -> InitializeParams {
    InitializeParams {
        version_range: VersionRange {
            minimum: PROVIDER_ABI_VERSION.to_owned(),
            maximum: PROVIDER_ABI_VERSION.to_owned(),
        },
        limits: HostLimits {
            max_frame_bytes: MAX_FRAME_BYTES as u32,
            max_json_depth: gorce_provider_abi::MAX_JSON_DEPTH as u16,
            max_members: gorce_provider_abi::MAX_JSON_MEMBERS as u16,
            max_timeout_ms: gorce_provider_abi::MAX_TIMEOUT_MS as u32,
        },
    }
}
