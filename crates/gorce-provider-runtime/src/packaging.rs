//! Packaging helpers shared by provider crates and their conformance tests.
//!
//! These helpers build the signed `.gorce-provider` ZIP for a manifest and an
//! executable image. Provider crates in this repository sign with bounded
//! deterministic fixture keys; the helpers are packaging support, not a
//! publisher signing service.

use ed25519_dalek::SigningKey;
use gorce_provider_abi::{manifest_bytes, sign_manifest, Manifest};
use std::io::Write;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

/// Build the signed provider archive: `manifest.json`, `signature.json`, and
/// the executable image at the manifest-declared path.
pub fn build_archive(
    manifest: &Manifest,
    signing_key: &SigningKey,
    executable_path: &str,
    executable_bytes: &[u8],
) -> Vec<u8> {
    let manifest_bytes = manifest_bytes(manifest).expect("provider manifest is bounded");
    let signature =
        sign_manifest(&manifest_bytes, signing_key).expect("provider manifest signing is valid");
    let signature_bytes = serde_json::to_vec(&signature).expect("signature serializes to JSON");
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
        zip.start_file(executable_path, options)
            .expect("executable entry");
        zip.write_all(executable_bytes).expect("executable bytes");
        zip.finish().expect("provider archive");
    }
    output
}
