#![forbid(unsafe_code)]
//! OpenAI Codex subscription provider package.
//!
//! Ported from the cliAgent `codex` plugin: a public-client PKCE flow against
//! auth.openai.com and a single provider-native `web_search` tool served
//! against the ChatGPT Codex gateway. Upstream exposes no native page fetch,
//! so — as in the source plugin — no `web_fetch` tool is declared and fetch is
//! not emulated through search.

use ed25519_dalek::SigningKey;
use gorce_provider_abi::{
    compute_archive_digest, derive_tool_id, digest_hex, fingerprint_hex, AuthMethod,
    CallbackPolicy, Capabilities, ExecutableEntrypoint, Manifest, ManifestPackage,
    OAuthAuthorizationCodePkceDeclaration, PackageFile, PackagePublisher, SideEffect,
    ToolDeclaration, ABI_FORMAT,
};
use serde_json::json;

pub const PROVIDER_ID: &str = "codex";
pub const TOOL_WEB_SEARCH: &str = "web_search";
pub const AUTH_METHOD_ID: &str = "codex_oauth";
pub const CREDENTIAL_CLASS: &str = "openai-oauth";
pub const EXECUTABLE_PATH: &str = "bin/codex";

/// Vendor-issued public-client identifier used by the ChatGPT Codex flow.
pub const OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const AUTHORIZATION_ENDPOINT: &str = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
pub const API_ORIGIN: &str = "https://chatgpt.com";

pub const SENTINEL_SECRET: &str = "codex-secret-sentinel";

/// A bounded deterministic signing fixture. It is test material only; it is
/// not a publisher key and must never be used for a production package.
pub const FIXTURE_SEED: [u8; 32] = [0x52; 32];

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_SEED)
}

pub fn manifest_for_executable(executable_bytes: &[u8]) -> Manifest {
    let public_key = signing_key().verifying_key().to_bytes();
    let executable_sha256 = digest_hex(executable_bytes);
    Manifest {
        format: ABI_FORMAT.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        display_name: "Codex (OpenAI subscription)".to_owned(),
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
        auth_methods: vec![AuthMethod::OauthAuthorizationCodePkce(
            OAuthAuthorizationCodePkceDeclaration {
                id: AUTH_METHOD_ID.to_owned(),
                credential_class: CREDENTIAL_CLASS.to_owned(),
                label: "ChatGPT subscription (OAuth)".to_owned(),
                client_type: "public".to_owned(),
                client_id: OAUTH_CLIENT_ID.to_owned(),
                authorization_endpoint: AUTHORIZATION_ENDPOINT.to_owned(),
                token_endpoint: TOKEN_ENDPOINT.to_owned(),
                approved_origins: vec!["https://auth.openai.com".to_owned()],
                scopes: vec![
                    "openid".to_owned(),
                    "profile".to_owned(),
                    "email".to_owned(),
                    "offline_access".to_owned(),
                ],
                callback: CallbackPolicy::HostManaged,
                grant_type: "authorization_code".to_owned(),
                pkce_method: "S256".to_owned(),
            },
        )],
        capabilities: Capabilities {
            auth_method_ids: vec![AUTH_METHOD_ID.to_owned()],
            credential_classes: vec![CREDENTIAL_CLASS.to_owned()],
            network_origins: vec![API_ORIGIN.to_owned(), "https://auth.openai.com".to_owned()],
        },
        tools: vec![ToolDeclaration {
            name: TOOL_WEB_SEARCH.to_owned(),
            description: "OpenAI-hosted web search surfaced as a provider tool".to_owned(),
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
            auth_method_id: Some(AUTH_METHOD_ID.to_owned()),
            credential_class: Some(CREDENTIAL_CLASS.to_owned()),
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
