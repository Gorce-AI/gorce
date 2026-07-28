#![forbid(unsafe_code)]

//! `gorce.provider/v1` is deliberately independent of the daemon and of the
//! client protocol.  It describes a signed package and the small JSON-RPC
//! surface spoken by a provider process over NDJSON.

mod manifest;
mod rpc;
mod signing;
mod source;
mod validation;

pub use manifest::{
    derive_tool_id, host_tool_id, ApiKeyDeclaration, AuthMethod, CallbackPolicy, Capabilities,
    ExecutableEntrypoint, Manifest, ManifestPackage, OAuthAuthorizationCodePkceDeclaration,
    PackageFile, PackagePublisher, SideEffect, ToolDeclaration, ABI_FORMAT, MAX_AUTH_METHODS,
    MAX_FILE_SIZE_BYTES, MAX_FILE_TABLE_ENTRIES, MAX_MANIFEST_BYTES, MAX_TOOLS,
};
pub use rpc::{
    decode_frame, decode_frame_with_limits, decode_request, decode_request_with_limits,
    decode_response, decode_response_with_limits, encode_message, request_id_from_frame,
    validate_frame, validate_frame_with_limits, AuthorizedInvocation, CancelParams, DeliveryKind,
    ErrorObject, HostLimits, InitializeParams, InitializeResult, InvokeResult, JsonRpcRequest,
    JsonRpcResponse, OperationCancelParams, RequestId, RpcCodecError, RuntimeCapabilities,
    ScopedSecretDelivery, SessionState, ShutdownParams, ToolDescriptor, ToolInvokeParams,
    ToolResult, VersionRange, MAX_FRAME_BYTES, MAX_HOST_FRAME_BYTES, MAX_HOST_JSON_DEPTH,
    MAX_HOST_JSON_MEMBERS, MAX_ID_BYTES, MAX_JSON_DEPTH, MAX_JSON_MEMBERS, MAX_REASON_BYTES,
    MAX_REQUEST_ID_BYTES, MAX_SECRET_BYTES, MAX_TIMEOUT_MS, MAX_TOOL_ID_BYTES, METHOD_CANCEL,
    METHOD_INITIALIZE, METHOD_SHUTDOWN, METHOD_TOOL_INVOKE,
};
pub use signing::{
    compute_archive_digest, digest_hex, fingerprint_hex, manifest_bytes, sign_manifest,
    verify_provider_archive, DetachedSignature, SignatureAlgorithm, SignatureError,
    SignedProviderPackage, VerifiedProviderArchive, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES, PROVIDER_ARCHIVE_EXTENSION, RESERVED_ARCHIVE_ENTRIES,
};
#[cfg(feature = "test-fixtures")]
pub use source::{test_verified_source_fixture, TestVerifiedSourceFixture};
pub use source::{
    verify_provider_source, GitHashAlgorithm, PinnedGitSource, ResolverOwnedGitSnapshot,
    SourceVerificationError, VerifiedProviderSource, VerifiedSourceFile, MAX_SOURCE_FILES,
    MAX_SOURCE_FILE_SIZE_BYTES, MAX_SOURCE_TOTAL_BYTES, SOURCE_CONTENT_DIGEST_ALGORITHM,
};
pub use validation::{
    validate_json_value, validate_local_schema, ValidationError, ValidationResult,
    MAX_RUNTIME_MEMBERS, MAX_RUNTIME_STRING_BYTES, MAX_SCHEMA_BYTES, MAX_SCHEMA_DEPTH,
    MAX_SCHEMA_NODES,
};

pub type SignedManifest = SignedProviderPackage;
pub type ProviderManifest = Manifest;

/// The package ABI is versioned independently of `gorce-protocol`.
pub const PROVIDER_ABI_VERSION: &str = "gorce.provider/v1";

/// A provider is trusted only after explicit approval of its signed package
/// and capabilities.  This is a trust decision, not a sandbox guarantee: a
/// trusted package executes as the user and can copy a secret delivered to it.
pub const TRUST_MODEL: &str = "trusted-after-explicit-approval; not sandboxed";

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn framing_requires_lf_and_rejects_depth_and_member_escalation() {
        assert!(decode_frame(b"{}").is_err());
        assert!(decode_frame(b"{}\r\n").is_err());
        assert!(decode_frame(&vec![b'a'; MAX_FRAME_BYTES + 1]).is_err());
        let mut deep = json!({});
        for _ in 0..=MAX_JSON_DEPTH {
            deep = json!({"nested": deep});
        }
        assert!(decode_frame(format!("{}\n", deep).as_bytes()).is_err());
        let members = (0..=MAX_JSON_MEMBERS)
            .map(|index| (format!("field-{index}"), json!(true)))
            .collect::<serde_json::Map<_, _>>();
        assert!(decode_frame(format!("{}\n", json!(members)).as_bytes()).is_err());
    }

    #[test]
    fn local_schema_rejects_unknown_keywords_and_validates_runtime_metadata() {
        assert!(validate_local_schema(&json!({"pattern": "x"}), "schema").is_err());
        assert!(
            validate_local_schema(&json!({"type": "string", "minLength": "bad"}), "schema")
                .is_err()
        );
        let schema = json!({
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1}},
            "required": ["query"],
            "additionalProperties": false
        });
        assert!(validate_json_value(&schema, &json!({"query": "ok"})).is_ok());
        assert!(validate_json_value(&schema, &json!({"query": ""})).is_err());
        assert!(validate_json_value(&schema, &json!({"query": "ok", "extra": true})).is_err());
    }

    #[test]
    fn shared_provider_fixtures_cover_manifest_and_response_invariants() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/provider-abi-fixtures.json"
        ))
        .unwrap();
        for fixture in fixtures["positive"].as_array().unwrap() {
            match fixture["kind"].as_str().unwrap() {
                "manifest" => {
                    let manifest: Manifest =
                        serde_json::from_value(fixture["value"].clone()).unwrap();
                    manifest.validate().unwrap();
                }
                "response" => {
                    let response: JsonRpcResponse =
                        serde_json::from_value(fixture["value"].clone()).unwrap();
                    response.validate().unwrap();
                }
                kind => panic!("unknown positive provider fixture kind: {kind}"),
            }
        }
        for fixture in fixtures["negative"].as_array().unwrap() {
            let valid = match fixture["kind"].as_str().unwrap() {
                "manifest" => serde_json::from_value::<Manifest>(fixture["value"].clone())
                    .unwrap()
                    .validate()
                    .is_ok(),
                "response" => serde_json::from_value::<JsonRpcResponse>(fixture["value"].clone())
                    .unwrap()
                    .validate()
                    .is_ok(),
                kind => panic!("unknown negative provider fixture kind: {kind}"),
            };
            assert!(!valid, "fixture unexpectedly passed: {}", fixture["reason"]);
        }
    }

    #[test]
    fn responses_are_exclusive_and_oauth_urls_use_canonical_https_origins() {
        let response = JsonRpcResponse::success(
            RequestId::new("response-1").unwrap(),
            &json!({
                "ok": true
            }),
        )
        .unwrap();
        let limits = HostLimits {
            max_frame_bytes: MAX_FRAME_BYTES as u32,
            max_json_depth: MAX_JSON_DEPTH as u16,
            max_members: MAX_JSON_MEMBERS as u16,
            max_timeout_ms: MAX_TIMEOUT_MS as u32,
        };
        let frame = encode_message(&response).unwrap();
        assert!(decode_response_with_limits(&frame, &limits).is_ok());
        assert!(decode_response(
            b"{\"jsonrpc\":\"2.0\",\"id\":\"response-null\",\"result\":null}\n"
        )
        .is_ok());
        let both = json!({
            "jsonrpc": "2.0", "id": "response-2", "result": {},
            "error": {"code": -1, "message": "bad"}
        });
        assert!(decode_response(&format!("{}\n", both).into_bytes()).is_err());

        let valid = oauth_manifest("https://example.com/authorize", "https://example.com");
        assert!(valid.validate().is_ok(), "{:?}", valid.validate());
        let invalid = oauth_manifest("http://example.com/authorize", "https://example.com");
        assert!(invalid.validate().is_err());
        let invalid_origin =
            oauth_manifest("https://example.com/authorize?x=1", "https://example.com");
        assert!(invalid_origin.validate().is_err());
    }

    fn oauth_manifest(endpoint: &str, approved_origin: &str) -> Manifest {
        let mut value = json!({
            "format": "gorce.provider/v1", "provider_id": "oauth-fixture",
            "display_name": "OAuth fixture", "version": "1.0.0",
            "publisher": {"name": "Fixture", "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "package": {"files": [{"path": "bin/provider", "size": 1, "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}], "executable": {"path": "bin/provider", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
            "auth_methods": [{"kind": "oauth_authorization_code_pkce", "id": "oauth", "credential_class": "oauth-access", "label": "OAuth", "client_type": "public", "client_id": "vendor-public", "authorization_endpoint": endpoint, "token_endpoint": "https://example.com/token", "approved_origins": [approved_origin], "scopes": ["search.read"], "callback": "host_managed", "grant_type": "authorization_code", "pkce_method": "S256"}],
            "capabilities": {"auth_method_ids": ["oauth"], "credential_classes": ["oauth-access"], "network_origins": [approved_origin]},
            "tools": [{"name": "search", "description": "Search", "input_schema": {"type": "object", "additionalProperties": false}, "output_schema": {"type": "object", "additionalProperties": false}, "side_effects": ["network_read"], "auth_method_id": "oauth", "credential_class": "oauth-access", "network_origins": [approved_origin]}]
        });
        serde_json::from_value(value.take()).unwrap()
    }
}
