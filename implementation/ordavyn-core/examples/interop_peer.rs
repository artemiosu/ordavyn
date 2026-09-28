//! Bounded local interop harness. Fixed keys are test-only, never production keys.
use ordavyn_core::transport::{OrdavynClient, OrdavynServer, PATH_PREFIX};
use ordavyn_core::{wire, Ed25519Keypair, Identifier, MessageType};
use std::io::{BufRead, Write};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let key = Ed25519Keypair::from_seed(std::array::from_fn(|i| i as u8));
    match args.get(1).map(String::as_str) {
        Some("tls-lifecycle") if args.len() == 2 => {
            tls_lifecycle().await?;
        }
        Some("sign") if args.len() == 3 => {
            let mut msg = wire::from_json(&std::fs::read(&args[2])?)?;
            msg.sign(&key)?;
            println!("{}", String::from_utf8(wire::to_json(&msg)?)?);
        }
        Some("client") if args.len() == 4 => {
            let msg = wire::from_json(&std::fs::read(&args[3])?)?;
            let scheme = if std::env::var_os("ORDAVYN_TLS_CA").is_some() {
                "https"
            } else {
                "http"
            };
            let mut client = OrdavynClient::new(&format!("{scheme}://127.0.0.1:{}", args[2]))
                .with_response_key(
                    ordavyn_core::Ed25519Keypair::from_seed([99; 32]).public_key(),
                    ordavyn_core::Identifier::new("participant", "service"),
                );
            if let Ok(ca) = std::env::var("ORDAVYN_TLS_CA") {
                client = client.with_tls(ordavyn_core::ClientTls::from_pem(
                    &std::fs::read(ca)?,
                    &std::env::var("ORDAVYN_TLS_NAME")?,
                )?);
            }
            if std::env::var_os("ORDAVYN_WRONG_PIN").is_some() {
                client = client.with_response_key(
                    Ed25519Keypair::from_seed([98; 32]).public_key(),
                    Identifier::new("participant", "service"),
                );
            }
            let result = client.send("/act", &msg).await?;
            println!("{}", String::from_utf8(wire::to_json(&result)?)?);
        }
        Some("server") if args.len() <= 3 => {
            let recipient = Identifier::new("participant", "service");
            let capacity = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(1000);
            let journal = Arc::new(if let Ok(path) = std::env::var("ORDAVYN_TEST_JOURNAL") {
                match std::env::var("ORDAVYN_TEST_JOURNAL_MODE")?.as_str() {
                    "create" => ordavyn_core::Journal::create(path, recipient.clone(), capacity)?,
                    "open" => ordavyn_core::Journal::open(path, recipient.clone(), capacity)?,
                    _ => return Err("test journal mode must be create or open".into()),
                }
            } else {
                ordavyn_core::Journal::memory(recipient.clone(), capacity)?
            });
            let mut configured = OrdavynServer::with_journal(recipient, capacity, journal.clone())?
                .with_signer(Ed25519Keypair::from_seed([99; 32]));
            if let Ok(cert) = std::env::var("ORDAVYN_TLS_CERT") {
                configured = configured.with_tls(ordavyn_core::ServerTls::from_pem(
                    &std::fs::read(cert)?,
                    &std::fs::read(std::env::var("ORDAVYN_TLS_KEY")?)?,
                )?);
            }
            let server = Arc::new(configured);
            server.trust(
                key.public_key(),
                Identifier::new("participant", "caller"),
                &["act"],
            )?;
            let count = Arc::new(AtomicUsize::new(0));
            for action in ["act", "denied"] {
                let effects = count.clone();
                server.handle(&format!("{PATH_PREFIX}/{action}"), move |mut msg| {
                    let n = effects.fetch_add(1, Ordering::SeqCst) + 1;
                    msg.msg_type = if msg.payload["value"] == "fail-after-effect" {
                        MessageType::Error
                    } else {
                        MessageType::Response
                    };
                    msg.payload = if msg.payload["value"] == "oversize" {
                        serde_json::json!({"echo":"\n".repeat(40000)})
                    } else if msg.msg_type == MessageType::Error {
                        serde_json::json!({"error":"simulated failure after effect"})
                    } else {
                        serde_json::json!({"effects":n, "echo":msg.payload["value"]})
                    };
                    msg
                });
            }
            // Bind synchronously to discover a port without a startup race; transfer it to tokio.
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let port = listener.local_addr()?.port();
            let async_listener = tokio::net::TcpListener::from_std(listener)?;
            // serve_listener_one owns its listener, so clone the OS listener for each bounded call.
            let listener = async_listener.into_std()?;
            let cloned = server.clone();
            let task = tokio::spawn(async move {
                loop {
                    let next =
                        tokio::net::TcpListener::from_std(listener.try_clone().unwrap()).unwrap();
                    let _ = cloned.serve_listener_one(next).await;
                }
            });
            println!("{port}");
            std::io::stdout().flush()?;
            // stdin commands make handler counters observable without adding an unprotected HTTP route.
            for line in std::io::stdin().lock().lines().take(200) {
                match line?.as_str() {
                    "count" => {
                        println!("{}", count.load(Ordering::SeqCst));
                        std::io::stdout().flush()?;
                    }
                    "reservations" => {
                        println!("{}", journal.inspect()?.len());
                        std::io::stdout().flush()?;
                    }
                    "states" => {
                        let states: Vec<_> = journal
                            .inspect()?
                            .into_iter()
                            .map(|entry| match entry.state {
                                ordavyn_core::Outcome::OutcomeUnknown => "outcome_unknown",
                                ordavyn_core::Outcome::HandlerReturned => "handler_returned",
                            })
                            .collect();
                        println!("{}", serde_json::to_string(&states)?);
                        std::io::stdout().flush()?;
                    }
                    "stop" => break,
                    _ => return Err("unknown command".into()),
                }
            }
            task.abort();
            let _ = task.await;
            assert!(server.stop(std::time::Duration::from_secs(4)).await);
            journal.close()?;
        }
        _ => {
            return Err(
                "usage: interop_peer server [CAPACITY] | sign FILE | client PORT FILE".into(),
            )
        }
    }
    Ok(())
}

// Test-only lifecycle exercise using temporary certificates supplied by the harness.
async fn tls_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    use ordavyn_core::{ClientTls, MessageBuilder, ServerTls};
    use std::time::Duration;
    let tls = ServerTls::from_pem(
        &std::fs::read(std::env::var("ORDAVYN_TLS_CERT")?)?,
        &std::fs::read(std::env::var("ORDAVYN_TLS_KEY")?)?,
    )?;
    let client_tls = ClientTls::from_pem(
        &std::fs::read(std::env::var("ORDAVYN_TLS_CA")?)?,
        "test.local",
    )?;
    let server = OrdavynServer::new()
        .with_signer(Ed25519Keypair::from_seed([99; 32]))
        .with_tls(tls);
    // Cancellation during handshake must release the accepted connection and listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let clone = server.clone();
    let task = tokio::spawn(async move { clone.serve_listener_one(listener).await });
    let socket = tokio::net::TcpStream::connect(address).await?;
    tokio::time::sleep(Duration::from_millis(30)).await;
    server.request_stop();
    assert!(server.stop(Duration::from_secs(1)).await);
    task.await??;
    drop(socket);
    server.resume()?;
    // Admitted synchronous handler survives cancellation of its TLS network task.
    let key = Ed25519Keypair::from_seed([42; 32]);
    server.trust(
        key.public_key(),
        Identifier::new("participant", "caller"),
        &["act"],
    )?;
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let entered = Arc::new(AtomicUsize::new(0));
    let handler_gate = gate.clone();
    let handler_entered = entered.clone();
    server.handle("/ordavyn/v3/act", move |mut msg| {
        handler_entered.store(1, Ordering::SeqCst);
        let (lock, signal) = &*handler_gate;
        let (open, _) = signal
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |open| !*open)
            .unwrap();
        assert!(*open);
        msg.payload = serde_json::json!({"ok":true});
        msg
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let clone = server.clone();
    let task = tokio::spawn(async move { clone.serve_listener_one(listener).await });
    let mut msg = MessageBuilder::new(
        Identifier::new("participant", "caller"),
        Identifier::new("participant", "service"),
    )
    .payload(serde_json::json!({"action":"act"}))
    .build();
    msg.sign(&key)?;
    let client = tokio::spawn(async move {
        OrdavynClient::new(&format!("https://{address}"))
            .with_response_key(
                Ed25519Keypair::from_seed([99; 32]).public_key(),
                Identifier::new("participant", "service"),
            )
            .with_tls(client_tls)
            .send("/act", &msg)
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while entered.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    task.abort();
    let _ = task.await;
    assert!(!server.stop(Duration::ZERO).await);
    assert!(server.resume().is_err());
    let (lock, signal) = &*gate;
    *lock.lock().unwrap() = true;
    signal.notify_all();
    assert!(server.stop(Duration::from_secs(3)).await);
    server.resume()?;
    let _ = client.await;
    println!("tls lifecycle passed");
    Ok(())
}
