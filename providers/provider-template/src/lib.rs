#![forbid(unsafe_code)]
//! Copy-me starter provider package.
//!
//! Ported from the cliAgent `provider-template` plugin. Every `EDIT ME`
//! constant is a placeholder: copy this crate, rename it, replace the
//! placeholder identifiers, endpoints, and origins with your vendor's values,
//! and implement the tool handlers in `main.rs`. The declared surface shows
//! both supported auth shapes — a plain API key and a public-client OAuth
//! PKCE flow — bound to a single `web_search` tool.

use ed25519_dalek::SigningKey;
use gorce_provider_abi::{
    compute_archive_digest, derive_tool_id, digest_hex, fingerprint_hex, ApiKeyDeclaration,
    AuthMethod, CallbackPolicy, Capabilities, ExecutableEntrypoint, Manifest, ManifestPackage,
    OAuthAuthorizationCodePkceDeclaration, PackageFile, PackagePublisher, SideEffect,
    ToolDeclaration, ABI_FORMAT,
};
use serde_json::json;

// ── EDIT ME: identity ────────────────────────────────────────────────────────
pub const PROVIDER_ID: &str = "provider-template";
pub const DISPLAY_NAME: &str = "Provider Template";
pub const EXECUTABLE_PATH: &str = "bin/provider-template";

// ── EDIT ME: API-key auth ────────────────────────────────────────────────────
pub const API_KEY_METHOD_ID: &str = "example_api_key";
pub const API_KEY_CREDENTIAL_CLASS: &str = "example-api-key";

// ── EDIT ME: OAuth PKCE auth (public client only in v1) ──────────────────────
pub const OAUTH_METHOD_ID: &str = "example_oauth";
pub const OAUTH_CREDENTIAL_CLASS: &str = "example-oauth";
pub const OAUTH_CLIENT_ID: &str = "replace-with-your-public-client-id";
pub const AUTHORIZATION_ENDPOINT: &str = "https://auth.example.com/oauth/authorize";
pub const TOKEN_ENDPOINT: &str = "https://auth.example.com/oauth/token";

// ── EDIT ME: network surface ─────────────────────────────────────────────────
pub const API_ORIGIN: &str = "https://api.example.com";
pub const AUTH_ORIGIN: &str = "https://auth.example.com";

pub const TOOL_WEB_SEARCH: &str = "web_search";
pub const SENTINEL_SECRET: &str = "provider-template-secret-sentinel";

/// A bounded deterministic signing fixture. It is test material only; it is
/// not a publisher key and must never be used for a production package.
pub const FIXTURE_SEED: [u8; 32] = [0x53; 32];

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_SEED)
}

pub fn manifest_for_executable(executable_bytes: &[u8]) -> Manifest {
    let public_key = signing_key().verifying_key().to_bytes();
    let executable_sha256 = digest_hex(executable_bytes);
    Manifest {
        format: ABI_FORMAT.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        display_name: DISPLAY_NAME.to_owned(),
        version: "0.1.0".to_owned(),
        publisher: Some(PackagePublisher {
            name: "Gorce community providers fixture".to_owned(),
            fingerprint: fingerprint_hex(&public_key),
        }),
        package: ManifestPackage {
            files: vec![PackageFile {
                path: EXECUTABLE_PATH.to_owned(),
                size: executable_bytes.len() as u64,
                sha256: executable_sha256.clone(),
            }],
            executable: ExecutableEntrypoint {
                path: EXECUTABLE_PATH.to_owned(),
                sha256: executable_sha256,
            },
        },
        auth_methods: vec![
            AuthMethod::ApiKey(ApiKeyDeclaration {
                id: API_KEY_METHOD_ID.to_owned(),
                credential_class: API_KEY_CREDENTIAL_CLASS.to_owned(),
                label: "Example API key".to_owned(),
            }),
            AuthMethod::OauthAuthorizationCodePkce(OAuthAuthorizationCodePkceDeclaration {
                id: OAUTH_METHOD_ID.to_owned(),
                credential_class: OAUTH_CREDENTIAL_CLASS.to_owned(),
                label: "Example subscription (OAuth)".to_owned(),
                client_type: "public".to_owned(),
                client_id: OAUTH_CLIENT_ID.to_owned(),
                authorization_endpoint: AUTHORIZATION_ENDPOINT.to_owned(),
                token_endpoint: TOKEN_ENDPOINT.to_owned(),
                approved_origins: vec![AUTH_ORIGIN.to_owned()],
                scopes: vec!["offline_access".to_owned()],
                callback: CallbackPolicy::HostManaged,
                grant_type: "authorization_code".to_owned(),
                pkce_method: "S256".to_owned(),
            }),
        ],
        capabilities: Capabilities {
            auth_method_ids: vec![API_KEY_METHOD_ID.to_owned(), OAUTH_METHOD_ID.to_owned()],
            credential_classes: vec![
                API_KEY_CREDENTIAL_CLASS.to_owned(),
                OAUTH_CREDENTIAL_CLASS.to_owned(),
            ],
            network_origins: vec![API_ORIGIN.to_owned(), AUTH_ORIGIN.to_owned()],
        },
        tools: vec![ToolDeclaration {
            name: TOOL_WEB_SEARCH.to_owned(),
            description: "Example vendor web search surfaced as a provider tool".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 128},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 5}
                },
                "required": ["query"],
                "additionalProperties": false
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "results": {
                        "type": "array",
                        "maxItems": 5,
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "url": {"type": "string"},
                                "snippet": {"type": "string"}
                            },
                            "required": ["title", "url", "snippet"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["query", "results"],
                "additionalProperties": false
            }),
            side_effects: vec![SideEffect::NetworkRead],
            auth_method_id: Some(API_KEY_METHOD_ID.to_owned()),
            credential_class: Some(API_KEY_CREDENTIAL_CLASS.to_owned()),
            network_origins: vec![API_ORIGIN.to_owned()],
        }],
    }
}

pub fn archive_bytes_for_executable(executable_bytes: &[u8]) -> Vec<u8> {
    gorce_provider_runtime::packaging::build_archive(
        &manifest_for_executable(executable_bytes),
        &signing_key(),
        EXECUTABLE_PATH,
        executable_bytes,
    )
}

pub fn tool_id_for(archive_bytes: &[u8], tool_name: &str) -> String {
    derive_tool_id(
        &compute_archive_digest(archive_bytes),
        PROVIDER_ID,
        tool_name,
    )
}
