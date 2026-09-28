use ordavyn_core::transport::{OrdavynClient, OrdavynServer};
use ordavyn_core::{wire, Ed25519Keypair, Identifier, Journal, MessageBuilder};
use std::sync::Arc;

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
