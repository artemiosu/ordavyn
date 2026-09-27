use ordavyn_core::transport::{OrdavynClient, OrdavynServer, PATH_PREFIX};
use ordavyn_core::{
    Ed25519Keypair, Identifier, Message, MessageBuilder, MessageType, SignatureAlgorithm,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
fn setup(cap: usize, fail: bool) -> (OrdavynServer, Ed25519Keypair, Arc<AtomicUsize>) {
    let server = OrdavynServer::new();
    let server = if cap == 10000 {
        server
    } else {
        OrdavynServer::with_policy(Identifier::new("participant", "service"), cap)
    };
    let key = Ed25519Keypair::generate();
    server
        .trust(
            key.public_key(),
            Identifier::new("participant", "caller"),
            &["act"],
        )
        .unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let count = effects.clone();
    server.handle(&format!("{PATH_PREFIX}/act"), move |mut msg| {
        count.fetch_add(1, Ordering::SeqCst);
        if fail {
            panic!("after effect");
        }
        msg.msg_type = MessageType::Response;
        msg
    });
    (server, key, effects)
}
fn message(key: &Ed25519Keypair) -> Message {
    let mut msg = MessageBuilder::new(
        Identifier::new("participant", "caller"),
        Identifier::new("participant", "service"),
    )
    .payload(serde_json::json!({"action":"act","value":"тест"}))
    .build();
    msg.sign(key).unwrap();
    msg
}
#[test]
fn negative_matrix() {
    let (server, key, effects) = setup(10000, false);
    for case in 0..13 {
        let mut msg = message(&key);
        match case {
            0 => msg.signature = None,
            1 => msg.signature.as_mut().unwrap().bytes[0] ^= 1,
            2 => msg.payload["value"] = serde_json::json!(2),
            3 => msg.sign(&Ed25519Keypair::generate()).unwrap(),
            4 => msg.signature_alg = Some(SignatureAlgorithm::MLDSA65),
            5 => msg.encoding = "json".into(),
            6 => {
                msg.version = 2;
                msg.sign(&key).unwrap();
            }
            7 => {
                msg.msg_type = MessageType::Response;
                msg.sign(&key).unwrap();
            }
            8 => {
                msg.from = Identifier::new("participant", "stranger");
                msg.sign(&key).unwrap();
            }
            9 => {
                msg.to = Identifier::new("participant", "other");
                msg.sign(&key).unwrap();
            }
            10 => {
                msg.payload["action"] = serde_json::json!("other");
                msg.sign(&key).unwrap();
            }
            11 => {
                msg.id = Identifier::new("wrong", "id");
                msg.sign(&key).unwrap();
            }
            _ => msg.signature.as_mut().unwrap().algorithm = SignatureAlgorithm::MLDSA65,
        }
        assert!(
            server
                .dispatch(&format!("{PATH_PREFIX}/act"), &msg)
                .is_err(),
            "case {case}"
        );
    }
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let msg = message(&key);
    let response = server
        .dispatch(&format!("{PATH_PREFIX}/act"), &msg)
        .unwrap();
    assert!(!response.is_signed());
    assert_ne!(response.id, msg.id);
    assert!(msg.verify_signature(&key.public_key()).is_ok());
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}
#[test]
fn replay_concurrent_failure_operation_capacity() {
    let (server, key, effects) = setup(1, true);
    let msg = message(&key);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let s = &server;
            let m = &msg;
            scope.spawn(move || {
                let _ = s.dispatch(&format!("{PATH_PREFIX}/act"), m);
            });
        }
    });
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let mut retry = message(&key);
    retry.operation_id = msg.operation_id.clone();
    retry.sign(&key).unwrap();
    assert!(server
        .dispatch(&format!("{PATH_PREFIX}/act"), &retry)
        .is_err());
    assert!(server
        .dispatch(&format!("{PATH_PREFIX}/act"), &message(&key))
        .is_err());
    assert!(server
        .dispatch(&format!("{PATH_PREFIX}/act"), &msg)
        .is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}
#[test]
fn object_array_and_permission_and_size() {
    let (server, key, effects) = setup(10000, false);
    let mut msg = message(&key);
    msg.payload = serde_json::json!({"a":1});
    msg.sign(&key).unwrap();
    msg.payload = serde_json::json!(["a", 1]);
    assert!(msg.verify_signature(&key.public_key()).is_err());
    server
        .trust(
            key.public_key(),
            Identifier::new("participant", "caller"),
            &["other"],
        )
        .unwrap();
    assert!(server
        .dispatch(&format!("{PATH_PREFIX}/act"), &message(&key))
        .is_err());
    let mut msg = message(&key);
    msg.payload["value"] = serde_json::json!("a".repeat(65536));
    msg.sign(&key).unwrap();
    assert!(server
        .dispatch(&format!("{PATH_PREFIX}/act"), &msg)
        .is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn http_roundtrip_and_rejections() {
    for case in 0..5 {
        let (server, key, effects) = setup(10000, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            server.serve_listener_one(listener).await.unwrap();
        });
        let client = OrdavynClient::new(&format!("http://{addr}"));
        let mut msg = message(&key);
        if case == 1 {
            msg.signature = None;
        }
        if case == 2 {
            msg.version = 2;
            msg.sign(&key).unwrap();
        }
        if case == 3 {
            msg.to = Identifier::new("participant", "other");
            msg.sign(&key).unwrap();
        }
        let result = client
            .send(if case == 4 { "/wrong" } else { "/act" }, &msg)
            .await;
        assert_eq!(result.is_ok(), case == 0);
        assert_eq!(
            effects.load(Ordering::SeqCst),
            if case == 0 { 1 } else { 0 }
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn fragmented_http_and_input_metadata_limits() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for case in 0..7 {
        let (server, key, effects) = setup(10000, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            server.serve_listener_one(listener).await.unwrap();
        });
        let body = serde_json::to_vec(&message(&key)).unwrap();
        let version = if case == 1 { "2" } else { "1" };
        let length = if case == 2 { 65537 } else { body.len() };
        let extra = match case {
            3 => "Transfer-Encoding: chunked\r\n".to_string(),
            4 => "Content-Length: 1\r\n".to_string(),
            5 => format!("X-Padding: {}\r\n", "a".repeat(8192)),
            _ => String::new(),
        };
        let mut request=format!("POST {PATH_PREFIX}/act HTTP/1.1\r\nContent-Type: application/json\r\nx-ordavyn-version: {version}\r\nContent-Length: {length}\r\n{extra}\r\n").into_bytes();
        request.extend_from_slice(&body);
        if case == 6 {
            request.truncate(request.len() - 10);
        }
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        if case == 0 {
            for part in request.chunks(7) {
                socket.write_all(part).await.unwrap();
            }
        } else {
            socket.write_all(&request).await.unwrap();
        }
        socket.shutdown().await.unwrap();
        let mut response = Vec::new();
        let _ = socket.read_to_end(&mut response).await;
        assert_eq!(
            response.starts_with(b"HTTP/1.1 200 "),
            case == 0,
            "case {case}"
        );
        assert_eq!(
            effects.load(Ordering::SeqCst),
            if case == 0 { 1 } else { 0 }
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn client_rejects_response_version_and_limits() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for case in 0..3 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let reply=match case {
                0=>"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 2\r\nContent-Length: 2\r\n\r\n{}".to_string(),
                1=>"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 1\r\nContent-Length: 65537\r\n\r\n".to_string(),
                _=>format!("HTTP/1.1 200 OK\r\nX-Padding: {}\r\n\r\n","a".repeat(9000)),
            };
            let _ = sock.write_all(reply.as_bytes()).await;
        });
        let client = OrdavynClient::new(&format!("http://{addr}"));
        assert!(client
            .send("/act", &message(&Ed25519Keypair::generate()))
            .await
            .is_err());
        task.await.unwrap();
    }
}

#[tokio::test]
async fn http_replay_same_operation_has_one_effect() {
    let (server, key, effects) = setup(10000, false);
    let first = message(&key);
    for case in 0..3 {
        let server = server.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            server.serve_listener_one(listener).await.unwrap();
        });
        let mut request = if case == 2 {
            message(&key)
        } else {
            first.clone()
        };
        request.operation_id = first.operation_id.clone();
        request.sign(&key).unwrap();
        let result = OrdavynClient::new(&format!("http://{addr}"))
            .send("/act", &request)
            .await;
        assert_eq!(result.is_ok(), case == 0);
        task.await.unwrap();
    }
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn message_id_replay_with_fresh_operation_and_spare_capacity() {
    let (server, key, effects) = setup(10000, false);
    let first = message(&key);
    server
        .dispatch(&format!("{PATH_PREFIX}/act"), &first)
        .unwrap();
    let mut retry = message(&key);
    assert_ne!(retry.operation_id, first.operation_id);
    retry.id = first.id.clone();
    retry.sign(&key).unwrap();
    let err = server
        .dispatch(&format!("{PATH_PREFIX}/act"), &retry)
        .unwrap_err();
    assert!(err.to_string().contains("replay"));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    server
        .dispatch(&format!("{PATH_PREFIX}/act"), &message(&key))
        .unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 2);
}

#[test]
fn authorized_oversized_direct_request_fails_before_effect() {
    let (server, key, effects) = setup(10000, false);
    let mut big = message(&key);
    big.payload["value"] = serde_json::json!("a".repeat(65536));
    big.sign(&key).unwrap();
    big.verify_signature(&key.public_key()).unwrap();
    let err = server
        .dispatch(&format!("{PATH_PREFIX}/act"), &big)
        .unwrap_err();
    assert!(err.to_string().contains("message too large"));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    server
        .dispatch(&format!("{PATH_PREFIX}/act"), &message(&key))
        .unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn client_checks_each_response_correlation_field() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for case in 0..6 {
        let request = message(&Ed25519Keypair::generate());
        let mut response = MessageBuilder::new(request.to.clone(), request.from.clone())
            .operation_id(request.operation_id.clone())
            .subject(request.subject.clone())
            .epoch(request.epoch.clone())
            .msg_type(MessageType::Response)
            .payload(serde_json::json!({"ok":true}))
            .build();
        match case {
            1 => response.operation_id.value = "other".into(),
            2 => response.from.value = "other".into(),
            3 => response.to.value = "other".into(),
            4 => response.subject.target_id.value = "other".into(),
            5 => response.epoch.value = "other".into(),
            _ => (),
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = serde_json::to_vec(&response).unwrap();
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 1\r\nContent-Length: {}\r\n\r\n",body.len());
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        });
        let result = OrdavynClient::new(&format!("http://{addr}"))
            .send("/act", &request)
            .await;
        assert_eq!(result.is_ok(), case == 0, "correlation case {case}");
        task.await.unwrap();
    }
}

#[tokio::test]
async fn stalled_request_hits_server_deadline() {
    use ordavyn_core::security::TIMEOUT;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (server, _, effects) = setup(10000, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { server.serve_listener_one(listener).await });
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(b"POST /ordavyn/v1/act HTTP/1.1\r\n")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(
        TIMEOUT + std::time::Duration::from_secs(2),
        socket.read(&mut byte),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(n, 0);
    assert!(started.elapsed() >= TIMEOUT - std::time::Duration::from_millis(200));
    assert!(task
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn slow_response_hits_client_deadline() {
    use ordavyn_core::security::TIMEOUT;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 1\r\nContent-Length: 2\r\n\r\n{").await.unwrap();
        tokio::time::sleep(TIMEOUT + std::time::Duration::from_secs(5)).await;
    });
    let client = OrdavynClient::new(&format!("http://{addr}"));
    let request = message(&Ed25519Keypair::generate());
    let started = std::time::Instant::now();
    let err = tokio::time::timeout(
        TIMEOUT + std::time::Duration::from_secs(2),
        client.send("/act", &request),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(err.to_string().contains("deadline"));
    assert!(started.elapsed() >= TIMEOUT - std::time::Duration::from_millis(200));
    task.abort();
}
