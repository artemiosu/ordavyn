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
        Some("sign") if args.len() == 3 => {
            let mut msg = wire::from_json(&std::fs::read(&args[2])?)?;
            msg.sign(&key)?;
            println!("{}", String::from_utf8(wire::to_json(&msg)?)?);
        }
        Some("client") if args.len() == 4 => {
            let msg = wire::from_json(&std::fs::read(&args[3])?)?;
            let result = OrdavynClient::new(&format!("http://127.0.0.1:{}", args[2]))
                .send("/act", &msg)
                .await?;
            println!("{}", String::from_utf8(wire::to_json(&result)?)?);
        }
        Some("server") if args.len() <= 3 => {
            let server = Arc::new(OrdavynServer::with_policy(
                Identifier::new("participant", "service"),
                args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(1000),
            ));
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
                    msg.msg_type = MessageType::Response;
                    msg.payload = serde_json::json!({"effects":n, "echo":msg.payload["value"]});
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
                    "stop" => break,
                    _ => return Err("unknown command".into()),
                }
            }
            task.abort();
        }
        _ => {
            return Err(
                "usage: interop_peer server [CAPACITY] | sign FILE | client PORT FILE".into(),
            )
        }
    }
    Ok(())
}
