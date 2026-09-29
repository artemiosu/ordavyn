use ordavyn_core::transport::{OrdavynClient, OrdavynServer};
use ordavyn_core::{
    wire, ClientTls, Ed25519Keypair, Identifier, Journal, MessageBuilder, ServerTls,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempCertificates {
    root: PathBuf,
    cert: Vec<u8>,
    key: Vec<u8>,
    other_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Drop for TempCertificates {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .output()
        .expect("openssl must be available for TLS constructor tests");
    assert!(
        output.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn temporary_certificates() -> TempCertificates {
    let root = std::env::temp_dir().join(format!(
        "ordavyn-pem-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    openssl(
        &root,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=test.local",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-days",
            "1",
        ],
    );
    openssl(
        &root,
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            "other-key.pem",
        ],
    );
    openssl(
        &root,
        &["pkey", "-in", "key.pem", "-pubout", "-out", "public.pem"],
    );
    TempCertificates {
        cert: fs::read(root.join("cert.pem")).unwrap(),
        key: fs::read(root.join("key.pem")).unwrap(),
        other_key: fs::read(root.join("other-key.pem")).unwrap(),
        public_key: fs::read(root.join("public.pem")).unwrap(),
        root,
    }
}

fn request() -> ordavyn_core::Message {
    let mut message = MessageBuilder::new(
        Identifier::new("participant", "caller"),
        Identifier::new("participant", "service"),
    )
    .payload(serde_json::json!({"action":"act","value":1}))
    .build();
    message.sign(&Ed25519Keypair::from_seed([42; 32])).unwrap();
    message
}
#[test]
fn signer_required_before_reservation() {
    let recipient = Identifier::new("participant", "service");
    let journal = Arc::new(Journal::memory(recipient.clone(), 10).unwrap());
    let server = OrdavynServer::with_journal(recipient, 10, journal.clone()).unwrap();
    server
        .trust(
            Ed25519Keypair::from_seed([42; 32]).public_key(),
            Identifier::new("participant", "caller"),
            &["act"],
        )
        .unwrap();
    server.handle("/ordavyn/v3/act", |_| {
        panic!("unconfigured signer admitted a handler")
    });
    assert!(server
        .dispatch("/ordavyn/v3/act", &request())
        .unwrap_err()
        .to_string()
        .contains("signer"));
    assert!(journal.inspect().unwrap().is_empty());
}
#[tokio::test]
async fn pin_required_before_connect() {
    let error = OrdavynClient::new("not-even-a-url")
        .send("/act", &request())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("local response pin required"));
}
#[test]
fn complete_request_binding_includes_payload_and_signature() {
    let first = request();
    let mut changed = first.clone();
    changed.payload["value"] = serde_json::json!(2);
    changed.sign(&Ed25519Keypair::from_seed([42; 32])).unwrap();
    assert_eq!(first.id, changed.id);
    assert_eq!(first.operation_id, changed.operation_id);
    assert_ne!(
        wire::request_digest(&first).unwrap(),
        wire::request_digest(&changed).unwrap()
    );
    changed = first.clone();
    changed.sign(&Ed25519Keypair::from_seed([43; 32])).unwrap();
    assert_ne!(
        wire::request_digest(&first).unwrap(),
        wire::request_digest(&changed).unwrap()
    );
}

#[test]
fn tls_pem_reader_matrix_and_first_key_semantics() {
    let material = temporary_certificates();
    assert!(ClientTls::from_pem(&material.cert, "test.local").is_ok());
    assert!(ServerTls::from_pem(&material.cert, &material.key).is_ok());

    for invalid in [
        b"".as_slice(),
        b"not DER or PEM",
        b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
    ] {
        assert!(ClientTls::from_pem(invalid, "test.local").is_err());
        assert!(ServerTls::from_pem(invalid, &material.key).is_err());
    }
    let malformed_key = [
        b"-----BEGIN ".as_slice(),
        b"PRIVATE KEY",
        b"-----\nnot-base64\n-----END ",
        b"PRIVATE KEY",
        b"-----\n",
    ]
    .concat();
    for invalid in [b"".as_slice(), b"not DER or PEM", malformed_key.as_slice()] {
        assert!(ServerTls::from_pem(&material.cert, invalid).is_err());
    }
    assert!(ServerTls::from_pem(&material.cert, &material.other_key).is_err());

    let mut full_chain = material.cert.clone();
    full_chain.extend_from_slice(&material.cert);
    assert!(ServerTls::from_pem(&full_chain, &material.key).is_ok());
    full_chain
        .extend_from_slice(b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n");
    assert!(ServerTls::from_pem(&full_chain, &material.key).is_err());

    let mut first_valid = material.public_key.clone();
    first_valid.extend_from_slice(&material.key);
    first_valid.extend_from_slice(&material.other_key);
    assert!(ServerTls::from_pem(&material.cert, &first_valid).is_ok());
    let mut first_wrong = material.other_key.clone();
    first_wrong.extend_from_slice(&material.key);
    assert!(ServerTls::from_pem(&material.cert, &first_wrong).is_err());

    let crlf_cert = material
        .cert
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>()
        .join(&b"\r\n"[..]);
    let crlf_key = material
        .key
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>()
        .join(&b"\r\n"[..]);
    assert!(ClientTls::from_pem(&crlf_cert, "test.local").is_ok());
    assert!(ServerTls::from_pem(&crlf_cert, &crlf_key).is_ok());
}
