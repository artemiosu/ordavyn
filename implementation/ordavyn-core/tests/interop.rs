use ordavyn_core::{wire, Ed25519Keypair, Message};
use serde_json::{json, Value};
fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/wire-v3.json")).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn frozen_cross_language_vectors() {
    let key = Ed25519Keypair::from_seed(std::array::from_fn(|i| i as u8));
    for vector in fixture()["vectors"].as_array().unwrap() {
        let mut msg = wire::from_json(&serde_json::to_vec(&vector["message"]).unwrap()).unwrap();
        assert_eq!(
            hex(&msg.canonical_signable_bytes().unwrap()),
            vector["signable_hex"],
            "{}",
            vector["name"]
        );
        msg.verify_signature(&key.public_key()).unwrap();
        msg.sign(&key).unwrap();
        assert_eq!(
            hex(&msg.signature.as_ref().unwrap().bytes),
            vector["signature_hex"]
        );
        let decoded = wire::from_json(&wire::to_json(&msg).unwrap()).unwrap();
        assert_eq!(
            decoded.canonical_signable_bytes().unwrap(),
            msg.canonical_signable_bytes().unwrap()
        );
    }
}
#[test]
fn strict_json_rejections() {
    for case in fixture()["invalid_json"].as_array().unwrap() {
        assert!(
            wire::from_json(case["json"].as_str().unwrap().as_bytes()).is_err(),
            "{}",
            case["name"]
        );
    }
}
#[test]
fn required_fields_and_invalid_metadata() {
    let base = fixture()["vectors"][0]["message"].clone();
    for field in base.as_object().unwrap().keys() {
        let mut d = base.clone();
        d.as_object_mut().unwrap().remove(field);
        assert!(
            wire::from_json(&serde_json::to_vec(&d).unwrap()).is_err(),
            "{field}"
        );
    }
    for case in 0..12 {
        let mut d = base.clone();
        match case {
            0 => {
                d["msg_type"] = d["type"].take();
                d.as_object_mut().unwrap().remove("type");
            }
            1 => d["extra"] = Value::Null,
            2 => {
                d["id"].as_object_mut().unwrap().remove("version");
            }
            3 => {
                d["subject"]
                    .as_object_mut()
                    .unwrap()
                    .remove("closure_version");
            }
            4 => d["subject"]["target_id"]["extra"] = json!(0),
            5 => d["id"]["version"] = json!(true),
            6 => d["timestamp"]["nanos"] = json!(1.0),
            7 => d["version"] = json!(1),
            8 => d["encoding"] = json!("cbor"),
            9 => d["signature"] = json!(d["signature"].as_str().unwrap().to_uppercase()),
            10 => d["signature"] = Value::Null,
            _ => d["id"]["value"] = json!("я".repeat(129)),
        }
        assert!(
            wire::from_json(&serde_json::to_vec(&d).unwrap()).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn tree_limit_on_network_and_signing() {
    let mut d = fixture()["vectors"][0]["message"].clone();
    let mut v = json!(0);
    for _ in 0..30 {
        v = json!([v]);
    }
    d["payload"] = v;
    let mut msg: Message = wire::from_json(&serde_json::to_vec(&d).unwrap()).unwrap();
    msg.payload = json!([msg.payload]);
    assert!(wire::to_json(&msg).is_err());
    assert!(msg.sign(&Ed25519Keypair::from_seed([0; 32])).is_err());
    assert!(wire::from_json(&serde_json::to_vec(&msg).unwrap()).is_err());
}

#[test]
fn model_budget_independent_of_json_and_exact_boundary() {
    use ordavyn_core::transport::OrdavynServer;
    let key = Ed25519Keypair::from_seed(std::array::from_fn(|i| i as u8));
    let mut msg: Message =
        serde_json::from_value(fixture()["vectors"][0]["message"].clone()).unwrap();
    msg.payload = json!({"action":"act", "value":"\n".repeat(40000)});
    msg.sign(&key).unwrap();
    msg.verify_signature(&key.public_key()).unwrap();
    assert!(wire::to_json(&msg).is_err());
    let server =
        OrdavynServer::new().with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
    server
        .trust(key.public_key(), msg.from.clone(), &["act"])
        .unwrap();
    server.handle("/ordavyn/v3/act", |mut m| {
        m.payload = json!({"ok":true});
        m
    });
    assert!(server
        .dispatch("/ordavyn/v3/act", &msg)
        .is_ok_and(|m| m.msg_type == ordavyn_core::MessageType::Response));
    msg.payload = json!({"action":"act", "value":"x".repeat(64000)});
    // ciborium's serde encoding has the same size regardless of map ordering.
    let mut model = Vec::new();
    ciborium::ser::into_writer(&msg, &mut model).unwrap();
    msg.payload["value"] = json!("x".repeat(64000 + 65536 - model.len()));
    model.clear();
    ciborium::ser::into_writer(&msg, &mut model).unwrap();
    assert_eq!(model.len(), 65536);
    msg.sign(&key).unwrap();
    msg.verify_signature(&key.public_key()).unwrap();
    msg.payload["value"] = json!(format!("{}x", msg.payload["value"].as_str().unwrap()));
    assert!(wire::validate(&msg, false).is_err());
    assert!(msg.sign(&key).is_err());
    assert!(msg.verify_signature(&key.public_key()).is_err());
    assert!(server
        .dispatch("/ordavyn/v3/act", &msg)
        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
}

#[test]
fn sign_budget_failure_preserves_unsigned_original() {
    let key = Ed25519Keypair::from_seed([0; 32]);
    let mut msg: Message =
        serde_json::from_value(fixture()["vectors"][0]["message"].clone()).unwrap();
    msg.signature = None;
    msg.signature_alg = None;
    msg.key_id = None;
    msg.payload = json!({"value":"x".repeat(64000)});
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&msg, &mut bytes).unwrap();
    msg.payload["value"] = json!("x".repeat(64000 + 65480 - bytes.len()));
    let original = serde_json::to_value(&msg).unwrap();
    let mut candidate = msg.clone();
    candidate.signature_alg = Some(ordavyn_core::SignatureAlgorithm::Ed25519);
    candidate.key_id = Some(key.key_id());
    candidate.canonical_signable_bytes().unwrap();
    assert!(msg.sign(&key).is_err());
    assert_eq!(serde_json::to_value(&msg).unwrap(), original);
}

#[test]
fn fixed_request_binding_and_signed_responses() {
    let data = fixture();
    let request: Message = serde_json::from_value(data["binding_request"].clone()).unwrap();
    assert_eq!(
        wire::request_digest(&request).unwrap(),
        data["request_digest"].as_str().unwrap()
    );
    for vector in data["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["name"].as_str().unwrap().starts_with("signed-"))
    {
        let response: Message = serde_json::from_value(vector["message"].clone()).unwrap();
        assert_eq!(response.reply_to.as_ref(), Some(&request.id));
        assert_eq!(
            response.request_digest.as_deref(),
            data["request_digest"].as_str()
        );
    }
}
