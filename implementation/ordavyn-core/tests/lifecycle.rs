use ordavyn_core::transport::{OrdavynClient, OrdavynServer};
use ordavyn_core::{Ed25519Keypair, Identifier, Journal, Message, MessageBuilder, MessageType};
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
// Test rendezvous have bounded waits; unwinding releases blocked handlers.
struct Barrier {
    state: Mutex<usize>,
    changed: Condvar,
}
impl Barrier {
    fn new(participants: usize) -> Self {
        assert_eq!(participants, 2);
        Self {
            state: Mutex::new(0),
            changed: Condvar::new(),
        }
    }
    fn wait(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *state += 1;
        self.changed.notify_all();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |n| *n < 2)
            .unwrap_or_else(|e| e.into_inner());
        let ready = *state >= 2;
        drop(state);
        assert!(ready && !timeout.timed_out(), "test rendezvous deadline");
    }
    fn release(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = 2;
        self.changed.notify_all();
    }
}
struct ReleaseOnDrop(Arc<Barrier>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}
const ROUTE: &str = "/ordavyn/v3/act";
fn sender() -> Identifier {
    Identifier::new("participant", "caller")
}
fn recipient() -> Identifier {
    Identifier::new("participant", "service")
}
fn message(key: &Ed25519Keypair) -> Message {
    let mut msg = MessageBuilder::new(sender(), recipient())
        .payload(serde_json::json!({"action":"act"}))
        .build();
    msg.sign(key).unwrap();
    msg
}
fn setup(
    sqlite: bool,
) -> (
    OrdavynServer,
    Ed25519Keypair,
    Arc<Journal>,
    std::path::PathBuf,
) {
    let path = std::env::temp_dir().join(format!(
        "ordavyn-lifecycle-{}.sqlite",
        rand::random::<u128>()
    ));
    let journal = Arc::new(if sqlite {
        Journal::create(&path, recipient(), 100).unwrap()
    } else {
        Journal::memory(recipient(), 100).unwrap()
    });
    let server = OrdavynServer::with_journal(recipient(), 100, journal.clone())
        .unwrap()
        .with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
    let key = Ed25519Keypair::generate();
    server
        .trust(key.public_key(), sender(), &["act", "other"])
        .unwrap();
    (server, key, journal, path)
}
fn cleanup(journal: Arc<Journal>, path: std::path::PathBuf) {
    journal.close().unwrap();
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
}
#[tokio::test(flavor = "current_thread")]
async fn admission_precedes_management_and_clones_share_gate() {
    for sqlite in [false, true] {
        for operation in ["revoke", "rotate", "narrow", "stop"] {
            let (server, key, journal, path) = setup(sqlite);
            let entered = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let _release_on_exit = ReleaseOnDrop(release.clone());
            let (e, r) = (entered.clone(), release.clone());
            server.handle(ROUTE, move |msg| {
                e.wait();
                r.wait();
                msg
            });
            let clone = server.clone();
            let msg = message(&key);
            let request = msg.clone();
            let worker = std::thread::spawn(move || clone.dispatch(ROUTE, &request));
            entered.wait();
            let new = Ed25519Keypair::generate();
            match operation {
                "revoke" => assert!(server.revoke(&key.public_key()).unwrap()),
                "rotate" => server
                    .rotate_key(&key.public_key(), new.public_key())
                    .unwrap(),
                "narrow" => server
                    .trust(key.public_key(), sender(), &["other"])
                    .unwrap(),
                _ => {
                    server.request_stop();
                    assert!(!server.stop(Duration::ZERO).await);
                    assert!(server.resume().is_err());
                }
            }
            assert!(journal.close().is_err());
            assert!(server
                .clone()
                .dispatch(ROUTE, &message(&key))
                .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
            release.wait();
            assert_eq!(
                worker.join().unwrap().unwrap().msg_type,
                MessageType::Response
            );
            assert!(server.stop(Duration::ZERO).await);
            server.resume().unwrap();
            if operation == "revoke" {
                server.trust(key.public_key(), sender(), &["act"]).unwrap();
            }
            let mut retry = msg;
            if operation == "rotate" {
                retry.sign(&new).unwrap();
            }
            assert!(server
                .dispatch(ROUTE, &retry)
                .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
            cleanup(journal, path);
        }
    }
}
#[test]
fn management_precedes_admission_without_reservation() {
    for sqlite in [false, true] {
        for operation in ["revoke", "rotate", "narrow", "stop"] {
            let (server, key, journal, path) = setup(sqlite);
            server.handle(ROUTE, |_| panic!("must not execute"));
            let ready = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let _release_on_exit = ReleaseOnDrop(release.clone());
            let (r, go, clone, msg) = (
                ready.clone(),
                release.clone(),
                server.clone(),
                message(&key),
            );
            let worker = std::thread::spawn(move || {
                r.wait();
                go.wait();
                clone.dispatch(ROUTE, &msg)
            });
            ready.wait();
            match operation {
                "revoke" => {
                    server.revoke(&key.public_key()).unwrap();
                }
                "rotate" => server
                    .rotate_key(&key.public_key(), Ed25519Keypair::generate().public_key())
                    .unwrap(),
                "narrow" => server
                    .trust(key.public_key(), sender(), &["other"])
                    .unwrap(),
                _ => server.request_stop(),
            }
            release.wait();
            assert!(worker
                .join()
                .unwrap()
                .is_ok_and(|r| r.msg_type == MessageType::Error));
            assert!(journal.inspect().unwrap().is_empty());
            cleanup(journal, path);
        }
    }
}
#[tokio::test]
async fn trust_updates_rotation_conflicts_and_reopen() {
    for sqlite in [false, true] {
        let (server, key, journal, path) = setup(sqlite);
        server.handle(ROUTE, |m| m);
        server.handle("/ordavyn/v3/other", |m| m);
        assert!(server
            .trust(
                key.public_key(),
                Identifier::new("participant", "other"),
                &["act"]
            )
            .is_err());
        assert!(server.trust(key.public_key(), sender(), &[]).is_err());
        server
            .trust(key.public_key(), sender(), &["other"])
            .unwrap();
        assert!(server
            .dispatch(ROUTE, &message(&key))
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        let mut other = message(&key);
        other.payload = serde_json::json!({"action":"other"});
        other.sign(&key).unwrap();
        assert!(server
            .dispatch("/ordavyn/v3/other", &other)
            .is_ok_and(|m| m.msg_type == ordavyn_core::MessageType::Response));
        server.trust(key.public_key(), sender(), &["act"]).unwrap();
        let new = Ed25519Keypair::generate();
        server.trust(new.public_key(), sender(), &["act"]).unwrap();
        assert!(server
            .rotate_key(&key.public_key(), new.public_key())
            .is_err());
        assert!(server
            .rotate_key(&key.public_key(), key.public_key())
            .is_err());
        assert!(server
            .rotate_key(&Ed25519Keypair::generate().public_key(), key.public_key())
            .is_err());
        assert!(server.revoke(&new.public_key()).unwrap());
        assert!(!server.revoke(&new.public_key()).unwrap());
        let msg = message(&key);
        assert!(server
            .dispatch(ROUTE, &msg)
            .is_ok_and(|m| m.msg_type == ordavyn_core::MessageType::Response));
        server
            .rotate_key(&key.public_key(), new.public_key())
            .unwrap();
        assert!(server
            .dispatch(ROUTE, &message(&key))
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        let fresh = server.dispatch(ROUTE, &message(&new)).unwrap();
        assert_eq!(fresh.msg_type, MessageType::Response);
        assert_eq!(fresh.payload, serde_json::json!({"action":"act"}));
        let mut forbidden = message(&new);
        forbidden.payload = serde_json::json!({"action":"other"});
        forbidden.sign(&new).unwrap();
        assert!(server
            .dispatch("/ordavyn/v3/other", &forbidden)
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        let mut retry = message(&new);
        retry.operation_id = msg.operation_id;
        retry.sign(&new).unwrap();
        assert!(server
            .dispatch(ROUTE, &retry)
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        assert!(server.stop(Duration::ZERO).await);
        server.resume().unwrap();
        assert!(server
            .dispatch(ROUTE, &retry)
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        if sqlite {
            journal.close().unwrap();
            let reopened = Arc::new(Journal::open(&path, recipient(), 100).unwrap());
            let fresh = OrdavynServer::with_journal(recipient(), 100, reopened.clone())
                .unwrap()
                .with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
            fresh.handle(ROUTE, |m| m);
            fresh.trust(new.public_key(), sender(), &["act"]).unwrap();
            assert!(fresh
                .dispatch(ROUTE, &retry)
                .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
            assert!(fresh
                .dispatch(ROUTE, &message(&new))
                .is_ok_and(|m| m.msg_type == ordavyn_core::MessageType::Response));
            reopened.close().unwrap();
        }
        cleanup(journal, path);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn panic_and_completion_failure_release_activity() {
    for sqlite in [false, true] {
        let (server, key, journal, path) = setup(sqlite);
        server.handle(ROUTE, |_| panic!("handler panic"));
        let msg = message(&key);
        assert_eq!(
            server.dispatch(ROUTE, &msg).unwrap().msg_type,
            MessageType::Error
        );
        assert!(server.stop(Duration::ZERO).await);
        server.resume().unwrap();
        assert!(server
            .dispatch(ROUTE, &msg)
            .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
        cleanup(journal, path);
    }
    let (server, key, journal, path) = setup(true);
    let dbpath = path.clone();
    server.handle(ROUTE, move |m| {
        let db = rusqlite::Connection::open(&dbpath).unwrap();
        db.execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE ON operations BEGIN SELECT RAISE(FAIL, 'failure'); END;").unwrap(); m
    });
    let msg = message(&key);
    assert!(server
        .dispatch(ROUTE, &msg)
        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
    assert!(server.stop(Duration::ZERO).await);
    server.resume().unwrap();
    assert!(server
        .dispatch(ROUTE, &msg)
        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
    cleanup(journal, path);
}
#[tokio::test(flavor = "current_thread")]
async fn http_worker_does_not_block_runtime_and_survives_serve_cancellation() {
    for sqlite in [false, true] {
        for cancel in [false, true] {
            let (server, key, journal, path) = setup(sqlite);
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let entered = Mutex::new(Some(entered_tx));
            let release = Arc::new(Barrier::new(2));
            let _release_on_exit = ReleaseOnDrop(release.clone());
            let r = release.clone();
            server.handle(ROUTE, move |m| {
                entered.lock().unwrap().take().unwrap().send(()).unwrap();
                r.wait();
                m
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let clone = server.clone();
            let serving = tokio::spawn(async move { clone.serve_listener_one(listener).await });
            let msg = message(&key);
            let request = msg.clone();
            let client = tokio::spawn(async move {
                OrdavynClient::new(&format!("http://{addr}"))
                    .with_response_key(
                        ordavyn_core::Ed25519Keypair::from_seed([99; 32]).public_key(),
                        ordavyn_core::Identifier::new("participant", "service"),
                    )
                    .send("/act", &request)
                    .await
            });
            tokio::time::timeout(Duration::from_secs(3), entered_rx)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                serving.abort();
            }
            server.request_stop();
            assert!(!server.stop(Duration::ZERO).await);
            assert!(server.resume().is_err());
            assert!(server.serve_one("127.0.0.1:0").await.is_err());
            assert!(server
                .dispatch(ROUTE, &message(&key))
                .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
            assert!(journal.close().is_err());
            release.wait();
            let _ = serving.await;
            let _ = client.await;
            assert!(server.stop(Duration::from_secs(3)).await);
            server.resume().unwrap();
            assert!(server
                .dispatch(ROUTE, &msg)
                .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
            cleanup(journal, path);
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn stop_before_start_bind_failure_and_all_listener_entries() {
    let server =
        OrdavynServer::new().with_signer(ordavyn_core::Ed25519Keypair::from_seed([99; 32]));
    assert!(server.stop(Duration::ZERO).await);
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(server
        .serve(&occupied.local_addr().unwrap().to_string())
        .await
        .is_err());
    assert!(server.stop(Duration::ZERO).await);
    server.resume().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let future = server.serve_listener_one(listener);
    tokio::pin!(future);
    // Poll the listener into its accept wait without arbitrary timing assumptions.
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    );
    assert!(server.serve_one("127.0.0.1:0").await.is_err());
    server.request_stop();
    future.await.unwrap();
    assert!(server.stop(Duration::ZERO).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let future = server.serve_listener_one(listener);
    tokio::pin!(future);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    );
    server.request_stop();
    future.await.unwrap();
    assert!(server.stop(Duration::ZERO).await);
}
#[test]
fn handler_can_request_stop() {
    let (server, key, journal, path) = setup(false);
    let clone = server.clone();
    server.handle(ROUTE, move |m| {
        clone.request_stop();
        m
    });
    assert!(server
        .dispatch(ROUTE, &message(&key))
        .is_ok_and(|m| m.msg_type == ordavyn_core::MessageType::Response));
    assert!(server
        .dispatch(ROUTE, &message(&key))
        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
    server.resume().unwrap();
    cleanup(journal, path);
}

#[tokio::test(flavor = "current_thread")]
async fn http_revoke_and_rotate_both_orderings() {
    for sqlite in [false, true] {
        for operation in ["revoke", "rotate", "narrow"] {
            let rotate = operation == "rotate";
            for admission_first in [false, true] {
                let (server, key, journal, path) = setup(sqlite);
                let new = Ed25519Keypair::generate();
                let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
                let entered = Mutex::new(Some(entered_tx));
                let release = Arc::new(Barrier::new(2));
                let _release_on_exit = ReleaseOnDrop(release.clone());
                let r = release.clone();
                server.handle(ROUTE, move |m| {
                    assert!(admission_first, "revoked request executed");
                    entered.lock().unwrap().take().unwrap().send(()).unwrap();
                    r.wait();
                    m
                });
                let change = || {
                    if rotate {
                        server
                            .rotate_key(&key.public_key(), new.public_key())
                            .unwrap();
                    } else if operation == "narrow" {
                        server
                            .trust(key.public_key(), sender(), &["other"])
                            .unwrap();
                    } else {
                        assert!(server.revoke(&key.public_key()).unwrap());
                    }
                };
                if !admission_first {
                    change();
                }
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let clone = server.clone();
                let serving = tokio::spawn(async move { clone.serve_listener_one(listener).await });
                let msg = message(&key);
                let request = msg.clone();
                let client = tokio::spawn(async move {
                    OrdavynClient::new(&format!("http://{addr}"))
                        .with_response_key(
                            ordavyn_core::Ed25519Keypair::from_seed([99; 32]).public_key(),
                            ordavyn_core::Identifier::new("participant", "service"),
                        )
                        .send("/act", &request)
                        .await
                });
                if admission_first {
                    tokio::time::timeout(Duration::from_secs(3), entered_rx)
                        .await
                        .unwrap()
                        .unwrap();
                    change();
                    release.wait();
                    assert_eq!(
                        client.await.unwrap().unwrap().msg_type,
                        MessageType::Response
                    );
                } else {
                    assert!(client
                        .await
                        .unwrap()
                        .is_ok_and(|r| r.msg_type == MessageType::Error));
                    assert!(journal.inspect().unwrap().is_empty());
                }
                serving.await.unwrap().unwrap();
                assert!(server.stop(Duration::from_secs(3)).await);
                if admission_first {
                    server.resume().unwrap();
                    let mut retry = msg;
                    if rotate {
                        retry.sign(&new).unwrap();
                    } else {
                        server.trust(key.public_key(), sender(), &["act"]).unwrap();
                    }
                    assert!(server
                        .dispatch(ROUTE, &retry)
                        .map_or(true, |m| m.msg_type == ordavyn_core::MessageType::Error));
                }
                cleanup(journal, path);
            }
        }
    }
}

#[tokio::test]
async fn reservation_before_handler_management_boundary() {
    use ordavyn_core::security::SecurityPolicy;
    for sqlite in [false, true] {
        for operation in ["revoke", "rotate", "narrow", "stop"] {
            let (_, key, journal, path) = setup(sqlite);
            let policy = SecurityPolicy::with_journal(recipient(), 100, journal.clone()).unwrap();
            policy.trust(key.public_key(), sender(), &["act"]).unwrap();
            let request = message(&key);
            let admission = policy.authorize_and_reserve(&request, "act").unwrap();
            match operation {
                "revoke" => {
                    policy.revoke(&key.public_key()).unwrap();
                }
                "rotate" => policy
                    .rotate_key(&key.public_key(), Ed25519Keypair::generate().public_key())
                    .unwrap(),
                "narrow" => policy
                    .trust(key.public_key(), sender(), &["other"])
                    .unwrap(),
                _ => policy.request_stop(),
            }
            assert!(!policy.stop(Duration::ZERO).await);
            assert!(journal.close().is_err());
            assert!(policy.resume().is_err());
            // Existing ownership can complete even though new admission is closed.
            admission.complete().unwrap();
            drop(admission);
            assert!(policy.stop(Duration::ZERO).await);
            assert_eq!(
                journal.inspect().unwrap()[0].state,
                ordavyn_core::Outcome::HandlerReturned
            );
            cleanup(journal, path);
        }
    }
}
