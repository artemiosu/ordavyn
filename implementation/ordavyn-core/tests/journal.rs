use ordavyn_core::transport::OrdavynServer;
use ordavyn_core::{Ed25519Keypair, Identifier, Journal, MessageBuilder, MessageType, Outcome};
use std::sync::Arc;
fn recipient() -> Identifier {
    Identifier {
        namespace: "participant".into(),
        value: "service".into(),
        version: Some(u64::MAX),
    }
}
fn ids() -> (Identifier, Identifier, Identifier) {
    (
        Identifier::new("participant", "caller"),
        Identifier {
            namespace: "message".into(),
            value: "m".into(),
            version: Some(u64::MAX),
        },
        Identifier::new("logical-operation", "op"),
    )
}
fn path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("ordavyn-{}.sqlite", rand::random::<u128>()))
}
#[test]
fn adapters_replay_capacity_and_lifecycle() {
    let path = path();
    for journal in [
        Journal::memory(recipient(), 2).unwrap(),
        Journal::create(&path, recipient(), 2).unwrap(),
    ] {
        let j = Arc::new(journal);
        let (s, m, o) = ids();
        let t = j.reserve(&s, &m, &o).unwrap();
        assert_eq!(j.inspect().unwrap()[0].state, Outcome::OutcomeUnknown);
        assert!(j.close().is_err());
        t.complete().unwrap();
        assert!(t.complete().is_err());
        drop(t);
        assert_eq!(j.inspect().unwrap()[0].state, Outcome::HandlerReturned);
        assert!(j
            .reserve(&s, &m, &Identifier::new("logical-operation", "other"))
            .is_err());
        assert!(j
            .reserve(&s, &Identifier::new("message", "other"), &o)
            .is_err());
        drop(
            j.reserve(
                &s,
                &Identifier::new("message", "two"),
                &Identifier::new("logical-operation", "two"),
            )
            .unwrap(),
        );
        assert!(j
            .reserve(
                &s,
                &Identifier::new("message", "three"),
                &Identifier::new("logical-operation", "three")
            )
            .is_err());
        j.close().unwrap();
        assert!(j.inspect().is_err());
    }
    let j = Arc::new(Journal::open(&path, recipient(), 2).unwrap());
    let (s, m, o) = ids();
    assert!(j.reserve(&s, &m, &o).is_err());
    assert_eq!(j.inspect().unwrap()[0].message, m);
    j.close().unwrap();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn open_validates_metadata_schema_and_data() {
    let path = path();
    assert!(Journal::open(&path, recipient(), 2).is_err());
    assert!(!path.exists());
    Journal::create(&path, recipient(), 2)
        .unwrap()
        .close()
        .unwrap();
    assert!(Journal::create(&path, recipient(), 2).is_err());
    assert!(Journal::open(&path, recipient(), 3).is_err());
    assert!(Journal::open(&path, Identifier::new("participant", "wrong"), 2).is_err());
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("UPDATE metadata SET version=2", []).unwrap();
    assert!(Journal::open(&path, recipient(), 2).is_err());
    db.execute("UPDATE metadata SET version=1", []).unwrap();
    db.execute("CREATE TABLE extra(x)", []).unwrap();
    assert!(Journal::open(&path, recipient(), 2).is_err());
    drop(db);
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(Journal::open(&path, recipient(), 2).is_err());
    std::fs::remove_file(path).unwrap();
}
#[test]
fn completion_commit_failure_preserves_reservation() {
    let path = path();
    let j = Arc::new(Journal::create(&path, recipient(), 2).unwrap());
    let (s, m, o) = ids();
    let t = j.reserve(&s, &m, &o).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("BEGIN; SELECT * FROM operations;")
        .unwrap();
    assert!(t.complete().is_err());
    db.execute_batch("ROLLBACK").unwrap();
    drop(t);
    assert_eq!(j.inspect().unwrap()[0].state, Outcome::OutcomeUnknown);
    assert!(j.reserve(&s, &m, &o).is_err());
    j.close().unwrap();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn busy_reservation_never_admitted() {
    let path = path();
    let j = Arc::new(Journal::create(&path, recipient(), 2).unwrap());
    let (s, m, o) = ids();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(j.reserve(&s, &m, &o).is_err());
    db.execute_batch("ROLLBACK").unwrap();
    db.execute_batch("BEGIN; SELECT * FROM operations;")
        .unwrap();
    // Insert can run, but its COMMIT must fail while another connection reads.
    assert!(j.reserve(&s, &m, &o).is_err());
    db.execute_batch("ROLLBACK").unwrap();
    assert!(j.inspect().unwrap().is_empty());
    drop(j.reserve(&s, &m, &o).unwrap());
    j.close().unwrap();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn dispatch_failure_stays_unknown_and_success_is_recorded() {
    for failing in [true, false] {
        let j = Arc::new(Journal::memory(recipient(), 2).unwrap());
        let server = OrdavynServer::with_journal(recipient(), 2, j.clone())
            .unwrap()
            .with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
        let key = Ed25519Keypair::generate();
        let (s, _, _) = ids();
        server.trust(key.public_key(), s.clone(), &["act"]).unwrap();
        let guard = j.clone();
        server.handle("/ordavyn/v3/act", move |m| {
            assert!(guard.close().is_err());
            if failing {
                panic!("effect may have occurred");
            }
            let mut r = m;
            r.msg_type = MessageType::Response;
            r.payload = serde_json::json!({"ok":true});
            r
        });
        let mut msg = MessageBuilder::new(s, recipient())
            .payload(serde_json::json!({"action":"act"}))
            .build();
        msg.sign(&key).unwrap();
        server.dispatch("/ordavyn/v3/act", &msg).unwrap();
        assert!(server
            .dispatch("/ordavyn/v3/act", &msg)
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        assert_eq!(
            j.inspect().unwrap()[0].state,
            if failing {
                Outcome::OutcomeUnknown
            } else {
                Outcome::HandlerReturned
            }
        );
        j.close().unwrap();
    }
}

#[test]
fn durable_dispatch_never_reports_success_on_completion_commit_failure() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    let path = path();
    let j = Arc::new(Journal::create(&path, recipient(), 2).unwrap());
    let server = OrdavynServer::with_journal(recipient(), 2, j.clone())
        .unwrap()
        .with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
    let key = Ed25519Keypair::generate();
    let (s, _, _) = ids();
    server.trust(key.public_key(), s.clone(), &["act"]).unwrap();
    let reader = Arc::new(Mutex::new(rusqlite::Connection::open(&path).unwrap()));
    let held = reader.clone();
    let effects = Arc::new(AtomicUsize::new(0));
    let count = effects.clone();
    server.handle("/ordavyn/v3/act", move |mut msg| {
        let reader = held.lock().unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let state: String = reader
            .query_row("SELECT state FROM operations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "outcome_unknown"); // A different connection sees the committed admission before effect.
        count.fetch_add(1, Ordering::SeqCst);
        msg.msg_type = MessageType::Response;
        msg.payload = serde_json::json!({"ok":true});
        msg
    });
    let mut msg = MessageBuilder::new(s, recipient())
        .payload(serde_json::json!({"action":"act"}))
        .build();
    msg.sign(&key).unwrap();
    assert!(server
        .dispatch("/ordavyn/v3/act", &msg)
        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
    reader.lock().unwrap().execute_batch("ROLLBACK").unwrap();
    assert!(server
        .dispatch("/ordavyn/v3/act", &msg)
        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(j.inspect().unwrap()[0].state, Outcome::OutcomeUnknown);
    j.close().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn completion_is_scoped_to_sender() {
    let path = path();
    for durable in [false, true] {
        let j = Arc::new(if durable {
            Journal::create(&path, recipient(), 2).unwrap()
        } else {
            Journal::memory(recipient(), 2).unwrap()
        });
        let (sender, message, operation) = ids();
        let other = Identifier::new("participant", "other");
        let a = j.reserve(&sender, &message, &operation).unwrap();
        let b = j.reserve(&other, &message, &operation).unwrap();
        a.complete().unwrap();
        drop(a);
        drop(b);
        let check = |j: &Journal| {
            let rows = j.inspect().unwrap();
            assert_eq!(rows.len(), 2);
            for row in rows {
                assert_eq!(
                    row.state,
                    if row.sender == sender {
                        Outcome::HandlerReturned
                    } else {
                        Outcome::OutcomeUnknown
                    }
                );
            }
        };
        check(&j);
        j.close().unwrap();
        if durable {
            let reopened = Journal::open(&path, recipient(), 2).unwrap();
            check(&reopened);
            reopened.close().unwrap();
        }
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_error_and_invalid_response_stay_unknown_after_reopen() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for invalid in [false, true] {
        let path = path();
        let key = Ed25519Keypair::generate();
        let (sender, _, _) = ids();
        let mut msg = MessageBuilder::new(sender.clone(), recipient())
            .payload(serde_json::json!({"action":"act"}))
            .build();
        msg.sign(&key).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        for reopening in [false, true] {
            let j = Arc::new(if reopening {
                Journal::open(&path, recipient(), 2).unwrap()
            } else {
                Journal::create(&path, recipient(), 2).unwrap()
            });
            let server = OrdavynServer::with_journal(recipient(), 2, j.clone())
                .unwrap()
                .with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
            server
                .trust(key.public_key(), sender.clone(), &["act"])
                .unwrap();
            let effects = count.clone();
            server.handle("/ordavyn/v3/act", move |mut msg| {
                effects.fetch_add(1, Ordering::SeqCst);
                msg.msg_type = if invalid {
                    MessageType::Response
                } else {
                    MessageType::Error
                };
                msg.payload = if invalid {
                    serde_json::json!({"oversized":"x".repeat(65536)})
                } else {
                    serde_json::json!({"error":"application failure"})
                };
                msg
            });
            let result = server.dispatch("/ordavyn/v3/act", &msg);
            if reopening || invalid {
                assert!(result.is_ok_and(|r| r.msg_type == MessageType::Error));
            } else {
                assert_eq!(result.unwrap().msg_type, MessageType::Error);
            }
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(j.inspect().unwrap()[0].state, Outcome::OutcomeUnknown);
            drop(server);
            j.close().unwrap();
        }
        std::fs::remove_file(path).unwrap();
    }
}
