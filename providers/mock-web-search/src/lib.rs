use ed25519_dalek::SigningKey;
use gorce_provider_abi::{
    compute_archive_digest, derive_tool_id, digest_hex, fingerprint_hex, manifest_bytes,
    sign_manifest, ApiKeyDeclaration, AuthMethod, Capabilities, ExecutableEntrypoint, Manifest,
    ManifestPackage, PackageFile, PackagePublisher, SideEffect, SignedProviderPackage,
    ToolDeclaration, ABI_FORMAT,
};
use serde_json::json;
use std::io::Write;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

pub const PROVIDER_ID: &str = "mock-web-search";
pub const TOOL_NAME: &str = "web_search";
pub const CREDENTIAL_CLASS: &str = "search-api-key";
pub const SENTINEL_SECRET: &str = "mock-secret-sentinel";
pub const EXECUTABLE_PATH: &str = "bin/mock-web-search";
pub const ARCHIVE_BYTES: &[u8] = b"mock-web-search-archive-v1";
pub const EXECUTABLE_BYTES: &[u8] = b"mock-web-search-executable-v1";

/// A bounded deterministic signing fixture. It is test material only; it is
/// not a publisher key and must never be used for a production package.
pub const FIXTURE_SEED: [u8; 32] = [0x42; 32];

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_SEED)
}

pub fn archive_digest() -> String {
    compute_archive_digest(&archive_bytes())
}

pub fn manifest_for_executable(executable_bytes: &[u8]) -> Manifest {
    let public_key = signing_key().verifying_key().to_bytes();
    let executable_sha256 = digest_hex(executable_bytes);
    Manifest {
        format: ABI_FORMAT.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        display_name: "Deterministic Mock Web Search".to_owned(),
        version: "1.0.0".to_owned(),
        publisher: Some(PackagePublisher {
            name: "Gorce ABI fixture".to_owned(),
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
        auth_methods: vec![AuthMethod::ApiKey(ApiKeyDeclaration {
            id: "search_api_key".to_owned(),
            credential_class: CREDENTIAL_CLASS.to_owned(),
            label: "Mock search API key".to_owned(),
        })],
        capabilities: Capabilities {
            auth_method_ids: vec!["search_api_key".to_owned()],
            credential_classes: vec![CREDENTIAL_CLASS.to_owned()],
            network_origins: Vec::new(),
        },
        tools: vec![ToolDeclaration {
            name: TOOL_NAME.to_owned(),
            description: "Return deterministic search results for conformance tests".to_owned(),
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
            auth_method_id: Some("search_api_key".to_owned()),
            credential_class: Some(CREDENTIAL_CLASS.to_owned()),
            network_origins: Vec::new(),
        }],
    }
}

pub fn manifest() -> Manifest {
    manifest_for_executable(EXECUTABLE_BYTES)
}

pub fn archive_bytes_for_executable(executable_bytes: &[u8]) -> Vec<u8> {
    let manifest = manifest_for_executable(executable_bytes);
    let manifest_bytes = manifest_bytes(&manifest).expect("fixture manifest is bounded");
    let signature =
        sign_manifest(&manifest_bytes, &signing_key()).expect("fixture signing is valid");
    let signature_bytes = serde_json::to_vec(&signature).expect("fixture signature JSON");
    let mut output = Vec::new();
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut output));
        let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("manifest.json", options)
            .expect("manifest entry");
        zip.write_all(&manifest_bytes).expect("manifest bytes");
        zip.start_file("signature.json", options)
            .expect("signature entry");
        zip.write_all(&signature_bytes).expect("signature bytes");
        zip.start_file(EXECUTABLE_PATH, options)
            .expect("executable entry");
        zip.write_all(executable_bytes).expect("executable bytes");
        zip.finish().expect("fixture archive");
    }
    output
}

pub fn archive_bytes() -> Vec<u8> {
    archive_bytes_for_executable(EXECUTABLE_BYTES)
}

pub fn tool_id() -> String {
    derive_tool_id(&archive_digest(), PROVIDER_ID, TOOL_NAME)
}

pub fn signed_package() -> SignedProviderPackage {
    let bytes = manifest_bytes(&manifest()).expect("fixture manifest is bounded");
    let signature = sign_manifest(&bytes, &signing_key()).expect("fixture signing is valid");
    SignedProviderPackage {
        archive_digest: archive_digest(),
        manifest: String::from_utf8(bytes).expect("serde JSON is UTF-8"),
        signature,
    }
}
