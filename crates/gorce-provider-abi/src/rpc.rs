use std::fmt;

use serde::{de::DeserializeOwned, de::Error as DeError, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{
    derive_tool_id, host_tool_id, validate_json_value, AuthMethod, Manifest, SideEffect,
    ValidationError, ValidationResult, PROVIDER_ABI_VERSION,
};

pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_JSON_MEMBERS: usize = 256;
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_REQUEST_ID_BYTES: usize = MAX_ID_BYTES;
pub const MAX_TOOL_ID_BYTES: usize = 256;
pub const MAX_TIMEOUT_MS: u64 = 120_000;
pub const MAX_SECRET_BYTES: usize = 4096;
pub const MAX_REASON_BYTES: usize = 512;
pub const MAX_HOST_FRAME_BYTES: usize = MAX_FRAME_BYTES;
pub const MAX_HOST_JSON_DEPTH: usize = MAX_JSON_DEPTH;
pub const MAX_HOST_JSON_MEMBERS: usize = MAX_JSON_MEMBERS;

pub const METHOD_INITIALIZE: &str = "gorce.initialize";
pub const METHOD_TOOL_INVOKE: &str = "tool.invoke";
pub const METHOD_CANCEL: &str = "operation.cancel";
pub const METHOD_SHUTDOWN: &str = "gorce.shutdown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcCodecError {
    EmptyFrame,
    MissingLineFeed,
    OversizedFrame,
    MultipleFrames,
    InvalidJson(String),
    InvalidRpc(String),
    InvalidParams(String),
    Sequence(String),
}

impl fmt::Display for RpcCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFrame => write!(formatter, "empty NDJSON frame"),
            Self::MissingLineFeed => write!(formatter, "NDJSON frame must end with LF"),
            Self::OversizedFrame => write!(formatter, "NDJSON frame exceeds 64 KiB"),
            Self::MultipleFrames => write!(formatter, "input contains multiple NDJSON frames"),
            Self::InvalidJson(error) => write!(formatter, "invalid JSON frame: {error}"),
            Self::InvalidRpc(error) => write!(formatter, "invalid JSON-RPC message: {error}"),
            Self::InvalidParams(error) => write!(formatter, "invalid RPC params: {error}"),
            Self::Sequence(error) => write!(formatter, "invalid provider RPC sequence: {error}"),
        }
    }
}

impl std::error::Error for RpcCodecError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_request_id(&value)?;
        Ok(Self(value))
    }

    pub fn validate(&self) -> ValidationResult<()> {
        validate_request_id(&self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    pub params: Value,
}

#[derive(Clone, PartialEq, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

impl<'de> Deserialize<'de> for JsonRpcResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut object = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        for key in object.keys() {
            if !matches!(key.as_str(), "jsonrpc" | "id" | "result" | "error") {
                return Err(D::Error::custom(format!("unknown response field {key}")));
            }
        }
        let jsonrpc = serde_json::from_value(
            object
                .remove("jsonrpc")
                .ok_or_else(|| D::Error::custom("missing response jsonrpc"))?,
        )
        .map_err(D::Error::custom)?;
        let id = serde_json::from_value(
            object
                .remove("id")
                .ok_or_else(|| D::Error::custom("missing response id"))?,
        )
        .map_err(D::Error::custom)?;
        let result = object.remove("result");
        let error = object
            .remove("error")
            .map(serde_json::from_value)
            .transpose()
            .map_err(D::Error::custom)?;
        Ok(Self {
            jsonrpc,
            id,
            result,
            error,
        })
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorObject {
    pub code: i32,
    pub message: String,
}

impl ErrorObject {
    pub fn validate(&self) -> ValidationResult<()> {
        if self.message.is_empty()
            || self.message.len() > MAX_REASON_BYTES
            || self.message.chars().any(char::is_control)
        {
            return Err(ValidationError::new(
                "error.message",
                "error message is empty, oversized, or contains control text",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for JsonRpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcRequest")
            .field("jsonrpc", &self.jsonrpc)
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for JsonRpcResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcResponse")
            .field("jsonrpc", &self.jsonrpc)
            .field("id", &self.id)
            .field("result", &self.result.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Debug for ErrorObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorObject")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ToolInvokeParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolInvokeParams")
            .field("invocation", &self.invocation)
            .field("input", &"<redacted>")
            .field("secret_delivery", &self.secret_delivery)
            .finish()
    }
}

impl fmt::Debug for ToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolResult")
            .field("invocation_id", &self.invocation_id)
            .field("output", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub minimum: String,
    pub maximum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    pub max_frame_bytes: u32,
    pub max_json_depth: u16,
    pub max_members: u16,
    pub max_timeout_ms: u32,
}

impl HostLimits {
    pub fn validate(&self) -> ValidationResult<()> {
        if self.max_frame_bytes == 0 || self.max_frame_bytes as usize > MAX_HOST_FRAME_BYTES {
            return Err(ValidationError::new(
                "limits.max_frame_bytes",
                "exceeds ABI bound",
            ));
        }
        if self.max_json_depth == 0 || self.max_json_depth as usize > MAX_HOST_JSON_DEPTH {
            return Err(ValidationError::new(
                "limits.max_json_depth",
                "exceeds ABI bound",
            ));
        }
        if self.max_members == 0 || self.max_members as usize > MAX_HOST_JSON_MEMBERS {
            return Err(ValidationError::new(
                "limits.max_members",
                "exceeds ABI bound",
            ));
        }
        if self.max_timeout_ms == 0 || self.max_timeout_ms as u64 > MAX_TIMEOUT_MS {
            return Err(ValidationError::new(
                "limits.max_timeout_ms",
                "exceeds ABI bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeParams {
    pub version_range: VersionRange,
    pub limits: HostLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeResult {
    pub abi_version: String,
    pub provider_id: String,
    pub package_digest: String,
    pub tools: Vec<ToolDescriptor>,
    pub capabilities: RuntimeCapabilities,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapabilities {
    pub auth_method_ids: Vec<String>,
    pub tool_ids: Vec<String>,
    pub credential_classes: Vec<String>,
    pub network_origins: Vec<String>,
    pub side_effects: Vec<SideEffect>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolDescriptor {
    pub tool_id: String,
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub side_effects: Vec<SideEffect>,
    pub auth_method_id: Option<String>,
    pub credential_class: Option<String>,
    pub network_origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthorizedInvocation {
    pub package_digest: String,
    pub tool_id: String,
    pub invocation_id: String,
    pub auth_method_id: Option<String>,
    pub credential_class: Option<String>,
    pub delivery_kind: Option<DeliveryKind>,
    pub deadline_unix_ms: u64,
}

struct RequiredNullable<T> {
    present: bool,
    value: Option<T>,
}

impl<T> Default for RequiredNullable<T> {
    fn default() -> Self {
        Self {
            present: false,
            value: None,
        }
    }
}

impl<'de, T> Deserialize<'de> for RequiredNullable<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Value::deserialize(deserializer)?;
        let value = if raw.is_null() {
            None
        } else {
            Some(serde_json::from_value(raw).map_err(D::Error::custom)?)
        };
        Ok(Self {
            present: true,
            value,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolDescriptorWire {
    tool_id: String,
    name: String,
    description: String,
    input_schema: Value,
    output_schema: Value,
    side_effects: Vec<SideEffect>,
    #[serde(default)]
    auth_method_id: RequiredNullable<String>,
    #[serde(default)]
    credential_class: RequiredNullable<String>,
    network_origins: Vec<String>,
}

impl<'de> Deserialize<'de> for ToolDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ToolDescriptorWire::deserialize(deserializer)?;
        if !wire.auth_method_id.present {
            return Err(D::Error::custom("missing field auth_method_id"));
        }
        if !wire.credential_class.present {
            return Err(D::Error::custom("missing field credential_class"));
        }
        Ok(Self {
            tool_id: wire.tool_id,
            name: wire.name,
            description: wire.description,
            input_schema: wire.input_schema,
            output_schema: wire.output_schema,
            side_effects: wire.side_effects,
            auth_method_id: wire.auth_method_id.value,
            credential_class: wire.credential_class.value,
            network_origins: wire.network_origins,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedInvocationWire {
    package_digest: String,
    tool_id: String,
    invocation_id: String,
    #[serde(default)]
    auth_method_id: RequiredNullable<String>,
    #[serde(default)]
    credential_class: RequiredNullable<String>,
    #[serde(default)]
    delivery_kind: RequiredNullable<DeliveryKind>,
    deadline_unix_ms: u64,
}

impl<'de> Deserialize<'de> for AuthorizedInvocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuthorizedInvocationWire::deserialize(deserializer)?;
        for (present, field) in [
            (wire.auth_method_id.present, "auth_method_id"),
            (wire.credential_class.present, "credential_class"),
            (wire.delivery_kind.present, "delivery_kind"),
        ] {
            if !present {
                return Err(D::Error::custom(format!("missing field {field}")));
            }
        }
        Ok(Self {
            package_digest: wire.package_digest,
            tool_id: wire.tool_id,
            invocation_id: wire.invocation_id,
            auth_method_id: wire.auth_method_id.value,
            credential_class: wire.credential_class.value,
            delivery_kind: wire.delivery_kind.value,
            deadline_unix_ms: wire.deadline_unix_ms,
        })
    }
}

impl AuthorizedInvocation {
    pub fn validate(&self) -> ValidationResult<()> {
        validate_hex(&self.package_digest, "invocation.package_digest")?;
        validate_tool_id(&self.tool_id)?;
        validate_bounded_id(
            &self.invocation_id,
            "invocation.invocation_id",
            MAX_ID_BYTES,
        )?;
        if self.deadline_unix_ms == 0 {
            return Err(ValidationError::new(
                "invocation.deadline_unix_ms",
                "deadline must be non-zero",
            ));
        }
        if let Some(class) = &self.credential_class {
            validate_bounded_id(class, "invocation.credential_class", MAX_ID_BYTES)?;
        }
        if let Some(auth_method_id) = &self.auth_method_id {
            validate_bounded_id(auth_method_id, "invocation.auth_method_id", MAX_ID_BYTES)?;
        }
        match (
            self.auth_method_id.is_some(),
            self.credential_class.is_some(),
            self.delivery_kind.is_some(),
        ) {
            (false, false, false) | (true, true, true) => {}
            _ => {
                return Err(ValidationError::new(
                    "invocation.credentials",
                    "auth method, credential class, and delivery kind must be present together",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSecretDelivery {
    pub kind: DeliveryKind,
    pub credential_class: String,
    /// Copyable provider-process secret. It is intentionally not a refresh token.
    pub value: String,
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for ScopedSecretDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedSecretDelivery")
            .field("kind", &self.kind)
            .field("credential_class", &self.credential_class)
            .field("value", &"<redacted>")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryKind {
    ApiKey,
    AccessToken,
}

impl ScopedSecretDelivery {
    pub fn validate_for(&self, invocation: &AuthorizedInvocation) -> ValidationResult<()> {
        let class = invocation.credential_class.as_ref().ok_or_else(|| {
            ValidationError::new("delivery", "secret delivery requires credential scope")
        })?;
        if class != &self.credential_class {
            return Err(ValidationError::new(
                "delivery.credential_class",
                "scope mismatch",
            ));
        }
        if invocation.delivery_kind != Some(self.kind) {
            return Err(ValidationError::new(
                "delivery.kind",
                "delivery kind does not match authorized invocation",
            ));
        }
        if self.value.is_empty()
            || self.value.len() > MAX_SECRET_BYTES
            || self.value.chars().any(char::is_control)
        {
            return Err(ValidationError::new(
                "delivery.value",
                "secret delivery is empty or oversized",
            ));
        }
        if self.expires_at_unix_ms == 0 || self.expires_at_unix_ms > invocation.deadline_unix_ms {
            return Err(ValidationError::new(
                "delivery.expires_at_unix_ms",
                "delivery exceeds invocation deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInvokeParams {
    pub invocation: AuthorizedInvocation,
    pub input: Value,
    #[serde(default)]
    pub secret_delivery: Option<ScopedSecretDelivery>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResult {
    pub invocation_id: String,
    pub output: Value,
}

pub type InvokeResult = ToolResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelParams {
    pub invocation_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

pub type OperationCancelParams = CancelParams;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownParams {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    AwaitInitialize,
    Initialized,
    ShuttingDown,
}

impl SessionState {
    pub fn validate_request(&self, request: &JsonRpcRequest) -> Result<(), RpcCodecError> {
        match (self, request.method.as_str()) {
            (Self::AwaitInitialize, METHOD_INITIALIZE) => Ok(()),
            (Self::Initialized, METHOD_TOOL_INVOKE | METHOD_CANCEL | METHOD_SHUTDOWN) => Ok(()),
            (Self::ShuttingDown, _) => {
                Err(RpcCodecError::Sequence("message after shutdown".to_owned()))
            }
            (Self::AwaitInitialize, _) => Err(RpcCodecError::Sequence(
                "first request must be gorce.initialize".to_owned(),
            )),
            (Self::Initialized, METHOD_INITIALIZE) => Err(RpcCodecError::Sequence(
                "gorce.initialize may occur only once and first".to_owned(),
            )),
            _ => Err(RpcCodecError::Sequence(
                "method is not valid in this state".to_owned(),
            )),
        }
    }

    pub fn initialized(&mut self) {
        *self = Self::Initialized;
    }

    pub fn shutting_down(&mut self) {
        *self = Self::ShuttingDown;
    }
}

pub fn validate_frame(frame: &[u8]) -> Result<(), RpcCodecError> {
    if frame.is_empty() {
        return Err(RpcCodecError::EmptyFrame);
    }
    if frame.len() > MAX_FRAME_BYTES {
        return Err(RpcCodecError::OversizedFrame);
    }
    if !frame.ends_with(b"\n") {
        return Err(RpcCodecError::MissingLineFeed);
    }
    let without_newline = &frame[..frame.len() - 1];
    if without_newline.is_empty()
        || without_newline.contains(&b'\n')
        || without_newline.contains(&b'\r')
    {
        return Err(RpcCodecError::MultipleFrames);
    }
    Ok(())
}

pub fn decode_frame(frame: &[u8]) -> Result<Value, RpcCodecError> {
    decode_value(frame, MAX_FRAME_BYTES, MAX_JSON_DEPTH, MAX_JSON_MEMBERS)
}

pub fn validate_frame_with_limits(frame: &[u8], limits: &HostLimits) -> Result<(), RpcCodecError> {
    limits
        .validate()
        .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))?;
    validate_frame(frame)?;
    if frame.len() > limits.max_frame_bytes as usize {
        return Err(RpcCodecError::OversizedFrame);
    }
    let _ = decode_value(
        frame,
        limits.max_frame_bytes as usize,
        limits.max_json_depth as usize,
        limits.max_members as usize,
    )?;
    Ok(())
}

pub fn decode_frame_with_limits(frame: &[u8], limits: &HostLimits) -> Result<Value, RpcCodecError> {
    validate_frame_with_limits(frame, limits)?;
    decode_value(
        frame,
        limits.max_frame_bytes as usize,
        limits.max_json_depth as usize,
        limits.max_members as usize,
    )
}

fn decode_value(
    frame: &[u8],
    max_frame_bytes: usize,
    max_json_depth: usize,
    max_members: usize,
) -> Result<Value, RpcCodecError> {
    validate_frame(frame)?;
    if frame.len() > max_frame_bytes {
        return Err(RpcCodecError::OversizedFrame);
    }
    let bytes = &frame[..frame.len() - 1];
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| RpcCodecError::InvalidJson(error.to_string()))?;
    if !value.is_object() {
        return Err(RpcCodecError::InvalidRpc(
            "NDJSON message must be an object".to_owned(),
        ));
    }
    let mut member_count = 0;
    validate_json_limits(&value, 0, max_json_depth, max_members, &mut member_count)
        .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
    Ok(value)
}

pub fn encode_message<T: Serialize>(message: &T) -> Result<Vec<u8>, RpcCodecError> {
    let mut bytes = serde_json::to_vec(message)
        .map_err(|error| RpcCodecError::InvalidJson(error.to_string()))?;
    bytes.push(b'\n');
    validate_frame(&bytes)?;
    Ok(bytes)
}

pub fn decode_request(frame: &[u8]) -> Result<JsonRpcRequest, RpcCodecError> {
    let value = decode_frame(frame)?;
    let request: JsonRpcRequest = serde_json::from_value(value)
        .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
    request.validate()?;
    Ok(request)
}

pub fn decode_request_with_limits(
    frame: &[u8],
    limits: &HostLimits,
) -> Result<JsonRpcRequest, RpcCodecError> {
    let value = decode_frame_with_limits(frame, limits)?;
    let request: JsonRpcRequest = serde_json::from_value(value)
        .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
    request.validate()?;
    Ok(request)
}

/// Recover a usable host request ID without validating method parameters. This
/// is deliberately a bounded envelope-only operation used to correlate
/// parameter errors; unusable IDs must not be trusted by a provider process.
pub fn request_id_from_frame(frame: &[u8]) -> Option<RequestId> {
    let bytes = frame.strip_suffix(b"\n").unwrap_or(frame);
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let id = value.get("id")?.as_str()?;
    RequestId::new(id).ok()
}

pub fn decode_response(frame: &[u8]) -> Result<JsonRpcResponse, RpcCodecError> {
    let value = decode_frame(frame)?;
    let response: JsonRpcResponse = serde_json::from_value(value)
        .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
    response.validate()?;
    Ok(response)
}

pub fn decode_response_with_limits(
    frame: &[u8],
    limits: &HostLimits,
) -> Result<JsonRpcResponse, RpcCodecError> {
    let value = decode_frame_with_limits(frame, limits)?;
    let response: JsonRpcResponse = serde_json::from_value(value)
        .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
    response.validate()?;
    Ok(response)
}

impl JsonRpcResponse {
    pub fn success<T: Serialize>(id: RequestId, result: &T) -> Result<Self, RpcCodecError> {
        Ok(Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(
                serde_json::to_value(result)
                    .map_err(|error| RpcCodecError::InvalidJson(error.to_string()))?,
            ),
            error: None,
        })
    }

    pub fn failure(id: RequestId, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
            }),
        }
    }

    /// Encode a response using the host limits negotiated during
    /// initialization.  Keeping this check on the response write path makes
    /// it impossible for a provider to accidentally fall back to the ABI
    /// maximum after the host selected a smaller frame or JSON bound.
    pub fn encode_with_limits(&self, limits: &HostLimits) -> Result<Vec<u8>, RpcCodecError> {
        self.validate()?;
        let frame = encode_message(self)?;
        validate_frame_with_limits(&frame, limits)?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), RpcCodecError> {
        self.id
            .validate()
            .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
        if self.jsonrpc != "2.0" || self.result.is_some() == self.error.is_some() {
            return Err(RpcCodecError::InvalidRpc(
                "response must contain exactly one result or error".to_owned(),
            ));
        }
        if let Some(error) = &self.error {
            error
                .validate()
                .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
        }
        Ok(())
    }
}

impl JsonRpcRequest {
    pub fn validate(&self) -> Result<(), RpcCodecError> {
        if self.jsonrpc != "2.0" {
            return Err(RpcCodecError::InvalidRpc("jsonrpc must be 2.0".to_owned()));
        }
        self.id
            .validate()
            .map_err(|error| RpcCodecError::InvalidRpc(error.to_string()))?;
        if !self.params.is_object() {
            return Err(RpcCodecError::InvalidParams(
                "params must be an object".to_owned(),
            ));
        }
        match self.method.as_str() {
            METHOD_INITIALIZE => self.typed_params::<InitializeParams>()?.validate(),
            METHOD_TOOL_INVOKE => self.typed_params::<ToolInvokeParams>()?.validate_wire(),
            METHOD_CANCEL => self.typed_params::<CancelParams>()?.validate_wire(),
            METHOD_SHUTDOWN => self.typed_params::<ShutdownParams>()?.validate_wire(),
            other => Err(RpcCodecError::InvalidRpc(format!(
                "method {other} is not in provider v1"
            ))),
        }
    }

    pub fn typed_params<T: DeserializeOwned>(&self) -> Result<T, RpcCodecError> {
        serde_json::from_value(self.params.clone())
            .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))
    }
}

impl InitializeParams {
    pub fn validate(&self) -> Result<(), RpcCodecError> {
        if self.version_range.minimum != PROVIDER_ABI_VERSION
            || self.version_range.maximum != PROVIDER_ABI_VERSION
        {
            return Err(RpcCodecError::InvalidParams(
                "v1 requires an exact gorce.provider/v1 version range".to_owned(),
            ));
        }
        self.limits
            .validate()
            .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))
    }
}

impl ToolInvokeParams {
    fn validate_wire(&self) -> Result<(), RpcCodecError> {
        self.invocation
            .validate()
            .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))?;
        if let Some(delivery) = &self.secret_delivery {
            delivery
                .validate_for(&self.invocation)
                .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))?;
        }
        Ok(())
    }

    pub fn validate_for(&self, manifest: &Manifest, archive_digest: &str) -> ValidationResult<()> {
        self.invocation.validate()?;
        if self.invocation.package_digest != archive_digest {
            return Err(ValidationError::new(
                "invocation.package_digest",
                "does not match the installed archive",
            ));
        }
        let (digest, provider, name) = parse_tool_id(&self.invocation.tool_id)?;
        if digest != archive_digest
            || provider != manifest.provider_id
            || host_tool_id(archive_digest, provider, name) != self.invocation.tool_id
            || manifest.tool(name).is_none()
        {
            return Err(ValidationError::new(
                "invocation.tool_id",
                "tool ID is forged or undeclared",
            ));
        }
        let tool = manifest.tool(name).expect("checked above");
        match &tool.credential_class {
            Some(class) => {
                let tool_auth_method_id = tool.auth_method_id.as_ref().ok_or_else(|| {
                    ValidationError::new(
                        "tool.auth_method_id",
                        "credentialed tool requires an auth method binding",
                    )
                })?;
                let auth_method_id = self.invocation.auth_method_id.as_ref().ok_or_else(|| {
                    ValidationError::new(
                        "invocation.auth_method_id",
                        "credentialed tool requires an auth method",
                    )
                })?;
                if auth_method_id != tool_auth_method_id {
                    return Err(ValidationError::new(
                        "invocation.auth_method_id",
                        "does not match the tool authentication method",
                    ));
                }
                let auth_method = manifest.auth_method(auth_method_id).ok_or_else(|| {
                    ValidationError::new("invocation.auth_method_id", "auth method is not declared")
                })?;
                if auth_method.credential_class() != class
                    || self.invocation.credential_class.as_deref() != Some(class.as_str())
                {
                    return Err(ValidationError::new(
                        "invocation.credential_class",
                        "credential scope mismatch",
                    ));
                }
                let expected_kind = delivery_kind_for_auth(auth_method);
                if self.invocation.delivery_kind != Some(expected_kind) {
                    return Err(ValidationError::new(
                        "invocation.delivery_kind",
                        "delivery kind does not match auth method",
                    ));
                }
                let delivery = self.secret_delivery.as_ref().ok_or_else(|| {
                    ValidationError::new("secret_delivery", "credentialed tool requires delivery")
                })?;
                delivery.validate_for(&self.invocation)?;
            }
            None => {
                if self.invocation.auth_method_id.is_some()
                    || self.invocation.credential_class.is_some()
                    || self.invocation.delivery_kind.is_some()
                    || self.secret_delivery.is_some()
                {
                    return Err(ValidationError::new(
                        "invocation.credentials",
                        "credential delivery is not declared for this tool",
                    ));
                }
            }
        }
        validate_json_value(&tool.input_schema, &self.input)
            .map_err(|error| ValidationError::new("input", error.to_string()))
    }
}

impl CancelParams {
    fn validate_wire(&self) -> Result<(), RpcCodecError> {
        validate_bounded_id(&self.invocation_id, "invocation_id", MAX_ID_BYTES)
            .and_then(|_| {
                if self.reason.as_ref().is_some_and(|reason| {
                    reason.len() > 512 || reason.chars().any(char::is_control)
                }) {
                    Err(ValidationError::new("reason", "cancel reason is oversized"))
                } else {
                    Ok(())
                }
            })
            .map_err(|error| RpcCodecError::InvalidParams(error.to_string()))
    }
}

impl ShutdownParams {
    fn validate_wire(&self) -> Result<(), RpcCodecError> {
        if let Some(reason) = &self.reason {
            if reason.len() > 512 || reason.chars().any(char::is_control) {
                return Err(RpcCodecError::InvalidParams(
                    "shutdown reason is oversized".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl ToolResult {
    pub fn validate_for(
        &self,
        manifest: &Manifest,
        archive_digest: &str,
        tool_name: &str,
        invocation_id: &str,
    ) -> ValidationResult<()> {
        validate_bounded_id(&self.invocation_id, "invocation_id", MAX_ID_BYTES)?;
        if self.invocation_id != invocation_id {
            return Err(ValidationError::new(
                "invocation_id",
                "does not match authorized invocation",
            ));
        }
        let tool = manifest
            .tool(tool_name)
            .ok_or_else(|| ValidationError::new("tool", "tool is not declared"))?;
        let expected = derive_tool_id(archive_digest, &manifest.provider_id, tool_name);
        if !expected.contains(archive_digest) {
            return Err(ValidationError::new("tool_id", "digest binding failed"));
        }
        validate_json_value(&tool.output_schema, &self.output)
            .map_err(|error| ValidationError::new("output", error.to_string()))
    }
}

impl ToolDescriptor {
    pub fn from_manifest(
        manifest: &Manifest,
        archive_digest: &str,
        tool: &crate::ToolDeclaration,
    ) -> Self {
        Self {
            tool_id: derive_tool_id(archive_digest, &manifest.provider_id, &tool.name),
            name: tool.name.clone(),
            description: tool.description.clone(),
            input_schema: tool.input_schema.clone(),
            output_schema: tool.output_schema.clone(),
            side_effects: tool.side_effects.clone(),
            auth_method_id: tool.auth_method_id.clone(),
            credential_class: tool.credential_class.clone(),
            network_origins: tool.network_origins.clone(),
        }
    }

    pub fn validate_for(&self, manifest: &Manifest, archive_digest: &str) -> ValidationResult<()> {
        let tool = manifest
            .tool(&self.name)
            .ok_or_else(|| ValidationError::new("tool", "tool is not declared"))?;
        let expected = Self::from_manifest(manifest, archive_digest, tool);
        if self != &expected {
            return Err(ValidationError::new(
                "tool",
                "runtime metadata/schema differs from manifest",
            ));
        }
        Ok(())
    }
}

impl InitializeResult {
    pub fn validate_for(&self, manifest: &Manifest, archive_digest: &str) -> ValidationResult<()> {
        manifest.validate()?;
        if self.abi_version != PROVIDER_ABI_VERSION
            || self.provider_id != manifest.provider_id
            || self.package_digest != archive_digest
            || self.tools.len() != manifest.tools.len()
        {
            return Err(ValidationError::new(
                "initialize.result",
                "runtime identity differs from approved manifest",
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for tool in &self.tools {
            tool.validate_for(manifest, archive_digest)?;
            if !names.insert(tool.name.as_str()) {
                return Err(ValidationError::new(
                    "initialize.tools",
                    "duplicate runtime tool",
                ));
            }
        }
        if manifest
            .tools
            .iter()
            .any(|tool| !names.contains(tool.name.as_str()))
        {
            return Err(ValidationError::new(
                "initialize.tools",
                "runtime tool set is incomplete",
            ));
        }
        let expected = RuntimeCapabilities::from_manifest(manifest, archive_digest);
        if self.capabilities != expected {
            return Err(ValidationError::new(
                "initialize.capabilities",
                "runtime capability escalation or mismatch",
            ));
        }
        Ok(())
    }
}

impl RuntimeCapabilities {
    pub fn from_manifest(manifest: &Manifest, archive_digest: &str) -> Self {
        let mut side_effects = Vec::new();
        let mut tool_ids = Vec::new();
        for tool in &manifest.tools {
            tool_ids.push(derive_tool_id(
                archive_digest,
                &manifest.provider_id,
                &tool.name,
            ));
            for effect in &tool.side_effects {
                if !side_effects.contains(effect) {
                    side_effects.push(*effect);
                }
            }
        }
        Self {
            auth_method_ids: manifest.capabilities.auth_method_ids.clone(),
            tool_ids,
            credential_classes: manifest.capabilities.credential_classes.clone(),
            network_origins: manifest.capabilities.network_origins.clone(),
            side_effects,
        }
    }
}

fn parse_tool_id(value: &str) -> ValidationResult<(&str, &str, &str)> {
    let rest = value
        .strip_prefix(&format!("{PROVIDER_ABI_VERSION}/tool/"))
        .ok_or_else(|| ValidationError::new("tool_id", "tool ID is not a v1 host ID"))?;
    let (digest, rest) = rest
        .split_once('/')
        .ok_or_else(|| ValidationError::new("tool_id", "tool ID is incomplete"))?;
    let (provider, name) = rest
        .split_once('/')
        .ok_or_else(|| ValidationError::new("tool_id", "tool ID is incomplete"))?;
    if name.contains('/') {
        return Err(ValidationError::new(
            "tool_id",
            "tool ID contains extra path segments",
        ));
    }
    Ok((digest, provider, name))
}

fn validate_request_id(value: &str) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ValidationError::new(
            "id",
            "host request ID must be a bounded ASCII string",
        ));
    }
    Ok(())
}

fn validate_bounded_id(value: &str, field: &str, max: usize) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ValidationError::new(
            field,
            "contains invalid bounded ID bytes",
        ));
    }
    Ok(())
}

fn validate_tool_id(value: &str) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte))
    {
        return Err(ValidationError::new(
            "invocation.tool_id",
            "contains invalid bounded tool ID bytes",
        ));
    }
    Ok(())
}

fn delivery_kind_for_auth(method: &AuthMethod) -> DeliveryKind {
    match method {
        AuthMethod::ApiKey(_) => DeliveryKind::ApiKey,
        AuthMethod::OauthAuthorizationCodePkce(_) => DeliveryKind::AccessToken,
    }
}

fn validate_hex(value: &str, field: &str) -> ValidationResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ValidationError::new(
            field,
            "must be lower-case SHA-256 hex",
        ));
    }
    Ok(())
}

fn validate_json_limits(
    value: &Value,
    depth: usize,
    max_depth: usize,
    max_members: usize,
    member_count: &mut usize,
) -> ValidationResult<()> {
    if depth > max_depth {
        return Err(ValidationError::new(
            "frame",
            "JSON depth exceeds host limit",
        ));
    }
    match value {
        Value::Array(values) => {
            *member_count += values.len();
            if *member_count > max_members {
                return Err(ValidationError::new(
                    "frame",
                    "array members exceed host limit",
                ));
            }
            for child in values {
                validate_json_limits(child, depth + 1, max_depth, max_members, member_count)?;
            }
        }
        Value::Object(values) => {
            *member_count += values.len();
            if *member_count > max_members {
                return Err(ValidationError::new(
                    "frame",
                    "object members exceed host limit",
                ));
            }
            for child in values.values() {
                validate_json_limits(child, depth + 1, max_depth, max_members, member_count)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits(max_frame_bytes: usize, max_json_depth: usize, max_members: usize) -> HostLimits {
        HostLimits {
            max_frame_bytes: max_frame_bytes as u32,
            max_json_depth: max_json_depth as u16,
            max_members: max_members as u16,
            max_timeout_ms: MAX_TIMEOUT_MS as u32,
        }
    }

    fn response(result: Value) -> JsonRpcResponse {
        JsonRpcResponse::success(RequestId::new("response").unwrap(), &result).unwrap()
    }

    #[test]
    fn response_encoding_enforces_a_lower_negotiated_frame_limit() {
        let response = response(json!({"payload": "bounded"}));
        let encoded = encode_message(&response).unwrap();
        let lower = limits(encoded.len() - 1, MAX_JSON_DEPTH, MAX_JSON_MEMBERS);

        assert_eq!(encoded.len(), lower.max_frame_bytes as usize + 1);
        assert_eq!(
            response.encode_with_limits(&lower),
            Err(RpcCodecError::OversizedFrame)
        );
    }

    #[test]
    fn response_encoding_enforces_lower_negotiated_json_limits() {
        let response = response(json!({"nested": {"value": true}}));

        let shallow = limits(MAX_FRAME_BYTES, 1, MAX_JSON_MEMBERS);
        assert!(matches!(
            response.encode_with_limits(&shallow),
            Err(RpcCodecError::InvalidRpc(_))
        ));

        let few_members = limits(MAX_FRAME_BYTES, MAX_JSON_DEPTH, 2);
        assert!(matches!(
            response.encode_with_limits(&few_members),
            Err(RpcCodecError::InvalidRpc(_))
        ));
    }

    #[test]
    fn response_encoding_accepts_a_valid_lower_limit_when_the_response_fits() {
        let response = response(json!({"ok": true}));
        let encoded = encode_message(&response).unwrap();
        let lower = limits(encoded.len(), MAX_JSON_DEPTH, MAX_JSON_MEMBERS);

        let bounded = response.encode_with_limits(&lower).unwrap();
        assert_eq!(bounded.len(), encoded.len());
        assert!(bounded.len() <= lower.max_frame_bytes as usize);
        assert!(decode_response_with_limits(&bounded, &lower).is_ok());
    }

    #[test]
    fn required_nullable_rpc_fields_must_be_explicit() {
        let base: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/examples/tool-invoke.json"
        ))
        .unwrap();
        for field in ["auth_method_id", "credential_class", "delivery_kind"] {
            let mut missing = base.clone();
            missing["params"]["invocation"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            let request: JsonRpcRequest = serde_json::from_value(missing).unwrap();
            assert!(
                request.typed_params::<ToolInvokeParams>().is_err(),
                "{field}"
            );

            let mut explicit_null = base.clone();
            explicit_null["params"]["invocation"][field] = Value::Null;
            let request: JsonRpcRequest = serde_json::from_value(explicit_null).unwrap();
            assert!(
                request.typed_params::<ToolInvokeParams>().is_ok(),
                "{field}"
            );
        }
    }

    #[test]
    fn required_nullable_tool_descriptor_fields_must_be_explicit() {
        let document: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/initialize-result.schema.json"
        ))
        .unwrap();
        let base = document["examples"][0].clone();
        for field in ["auth_method_id", "credential_class"] {
            let mut missing = base.clone();
            missing["tools"][0].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<InitializeResult>(missing).is_err(),
                "{field}"
            );

            let mut explicit_null = base.clone();
            explicit_null["tools"][0][field] = Value::Null;
            assert!(
                serde_json::from_value::<InitializeResult>(explicit_null).is_ok(),
                "{field}"
            );
        }
    }

    #[test]
    fn shared_rpc_numeric_bounds_match_rust_types() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/provider-parity-fixtures.json"
        ))
        .unwrap();
        let invoke: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/examples/tool-invoke.json"
        ))
        .unwrap();
        for fixture in fixtures["numeric_bounds"].as_array().unwrap() {
            let kind = fixture["kind"].as_str().unwrap();
            let valid = match kind {
                "deadline" | "expiration" => {
                    let mut value = invoke["params"].clone();
                    if kind == "deadline" {
                        value["invocation"]["deadline_unix_ms"] = fixture["value"].clone();
                    } else {
                        value["secret_delivery"]["expires_at_unix_ms"] = fixture["value"].clone();
                    }
                    serde_json::from_value::<ToolInvokeParams>(value).is_ok()
                }
                "error_code" => {
                    let mut value = json!({
                        "jsonrpc": "2.0",
                        "id": "numeric-code",
                        "error": {"code": fixture["value"], "message": "error"}
                    });
                    serde_json::from_value::<JsonRpcResponse>(value.take()).is_ok()
                }
                _ => continue,
            };
            assert_eq!(valid, fixture["valid"].as_bool().unwrap(), "{kind}");
        }
    }
}
