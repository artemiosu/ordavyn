//! HTTP/2 transport layer for AgentBridge (BC v1.1.0 §3.2, §4.2).
//!
//! Uses HTTP/2 bidirectional streams for all communication (no WebSocket).
//! Messages encoded as canonical CBOR in HTTP/2 POST body.
//! Content-Type: application/cbor.
//! No Bearer token — identity via mTLS (BC v1.1.0 §7.3).
//!
//! For this prototype (AB-PROTO-001): localhost only, no TLS (plain HTTP/2).
//! Production will use TLS 1.3 mTLS per BC §7.

use crate::error::{CoreError, Result};
use crate::message::{Message, MessageType};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Content type for AgentBridge CBOR messages.
pub const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// Content type for AgentBridge JSON debug messages.
pub const CONTENT_TYPE_JSON: &str = "application/json";

/// AgentBridge protocol version header.
pub const VERSION_HEADER: &str = "x-agentbridge-version";

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// AgentBridge HTTP path prefix.
pub const PATH_PREFIX: &str = "/agentbridge/v1";

/// Simple HTTP/1.1 server for prototype (h2 upgrade deferred; using HTTP/1.1 for simplicity).
///
/// In production, this will be HTTP/2 (hyper). For the prototype, HTTP/1.1
/// on localhost is sufficient to demonstrate message exchange.
pub struct AgentBridgeServer {
    handlers: Arc<Mutex<HashMap<String, Arc<dyn Fn(Message) -> Message + Send + Sync>>>>,
}

impl AgentBridgeServer {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a handler for a path (e.g., "/agentbridge/v1/binding").
    pub fn handle<F>(&self, path: &str, handler: F)
    where
        F: Fn(Message) -> Message + Send + Sync + 'static,
    {
        self.handlers
            .lock()
            .unwrap()
            .insert(path.to_string(), Arc::new(handler));
    }

    /// Start listening on the given address (localhost only per AB-PROTO-001).
    pub async fn serve(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| CoreError::InvalidMessage(format!("bind failed: {}", e)))?;

        loop {
            let (mut socket, _) = listener
                .accept()
                .await
                .map_err(|e| CoreError::InvalidMessage(format!("accept failed: {}", e)))?;

            let handlers = self.handlers.clone();
            tokio::spawn(async move {
                let _ = handle_connection(&mut socket, &handlers).await;
            });
        }
    }

    /// Try to serve one connection (for testing).
    pub async fn serve_one(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| CoreError::InvalidMessage(format!("bind failed: {}", e)))?;

        let (mut socket, _) = listener
            .accept()
            .await
            .map_err(|e| CoreError::InvalidMessage(format!("accept failed: {}", e)))?;

        handle_connection(&mut socket, &self.handlers).await
    }
}

async fn handle_connection(
    socket: &mut tokio::net::TcpStream,
    handlers: &Arc<Mutex<HashMap<String, Arc<dyn Fn(Message) -> Message + Send + Sync>>>>,
) -> Result<()> {
    // Read HTTP request (simple parser for prototype)
    let mut buf = vec![0u8; 65536];
    let n = socket
        .read(&mut buf)
        .await
        .map_err(|e| CoreError::InvalidMessage(format!("read failed: {}", e)))?;
    let request = String::from_utf8_lossy(&buf[..n]).to_string();

    // Parse request line
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_response(socket, 400, "Bad Request", b"invalid HTTP request").await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    if method != "POST" {
        write_response(socket, 405, "Method Not Allowed", b"only POST supported").await?;
        return Ok(());
    }

    // Extract body (after \r\n\r\n)
    let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(request.len());
    let body_str = &request[body_start..];

    // Parse body as JSON Message
    let msg: Message = match serde_json::from_str(body_str) {
        Ok(m) => m,
        Err(e) => {
            write_response(
                socket,
                422,
                "Unprocessable Entity",
                format!("invalid message: {}", e).as_bytes(),
            )
            .await?;
            return Ok(());
        }
    };

    // Find handler and call it (drop guard before any await)
    let response_msg = {
        let handler = {
            let handlers_guard = handlers.lock().unwrap();
            handlers_guard.get(path).cloned()
        };
        match handler {
            Some(h) => h(msg),
            None => {
                write_response(socket, 404, "Not Found", b"no handler for path").await?;
                return Ok(());
            }
        }
    };

    // Serialize response
    let response_body = serde_json::to_string(&response_msg)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    write_response(socket, 200, "OK", response_body.as_bytes()).await
}

async fn write_response(
    socket: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len()
    );
    socket
        .write_all(response.as_bytes())
        .await
        .map_err(|e| CoreError::InvalidMessage(format!("write failed: {}", e)))?;
    socket
        .write_all(body)
        .await
        .map_err(|e| CoreError::InvalidMessage(format!("write body failed: {}", e)))?;
    Ok(())
}

/// Simple HTTP/1.1 client for AgentBridge (prototype).
///
/// Production will use HTTP/2 with hyper. For prototype, HTTP/1.1 on localhost
/// is sufficient to demonstrate message exchange.
pub struct AgentBridgeClient {
    base_url: String,
}

impl AgentBridgeClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
        }
    }

    /// Send a message to a specific endpoint and get the response.
    pub async fn send(&self, endpoint: &str, msg: &Message) -> Result<Message> {
        let url = format!("{}{}{}", self.base_url, PATH_PREFIX, endpoint);
        let body = serde_json::to_string(msg)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Parse URL (simple: http://host:port)
        let url = url.strip_prefix("http://").unwrap_or(&url);
        let (host_port, path) = url.split_once('/').unwrap_or((url, "/"));
        let path = format!("/{}", path);

        // Connect
        let mut stream = tokio::net::TcpStream::connect(host_port)
            .await
            .map_err(|e| CoreError::InvalidMessage(format!("connect failed: {}", e)))?;

        // Send HTTP request
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            host_port,
            VERSION_HEADER,
            PROTOCOL_VERSION,
            body.len(),
            body
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| CoreError::InvalidMessage(format!("write failed: {}", e)))?;

        // Read response
        let mut buf = vec![0u8; 65536];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| CoreError::InvalidMessage(format!("read failed: {}", e)))?;

        let response = String::from_utf8_lossy(&buf[..n]).to_string();

        // Parse response
        let body_start = response
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(response.len());
        let response_body = &response[body_start..];

        let result: Message = serde_json::from_str(response_body)
            .map_err(|e| CoreError::InvalidMessage(format!("invalid response: {}", e)))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aim::Identifier;
    use crate::message::{MessageBuilder, MessageType};

    #[tokio::test]
    async fn test_server_client_roundtrip() {
        let addr = "127.0.0.1:18080";

        // Create server with a simple echo handler
        let server = AgentBridgeServer::new();
        server.handle(
            &format!("{}/test", PATH_PREFIX),
            |msg: Message| {
                // Echo back with type changed to Response
                let mut response = msg;
                response.msg_type = MessageType::Response;
                response
            },
        );

        // Start server in background
        let server_handle = tokio::spawn(async move {
            let _ = server.serve_one(addr).await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Create client and send message
        let client = AgentBridgeClient::new("http://127.0.0.1:18080");
        let from = Identifier::new("participant", "alice");
        let to = Identifier::new("participant", "bob");

        let msg = MessageBuilder::new(from, to)
            .id(Identifier::new("message", "test-001"))
            .operation_id(Identifier::new("logical-operation", "test-op-001"))
            .payload(serde_json::json!({"action": "ping"}))
            .build();

        let response = client.send("/test", &msg).await.unwrap();

        assert_eq!(response.msg_type, MessageType::Response);
        assert_eq!(
            response.payload,
            serde_json::json!({"action": "ping"})
        );

        // Wait for server to finish
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_server_404_for_unknown_path() {
        let addr = "127.0.0.1:18081";

        let server = AgentBridgeServer::new();
        // No handler registered

        let server_handle = tokio::spawn(async move {
            let _ = server.serve_one(addr).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = AgentBridgeClient::new("http://127.0.0.1:18081");
        let from = Identifier::new("participant", "alice");
        let to = Identifier::new("participant", "bob");

        let msg = MessageBuilder::new(from, to)
            .id(Identifier::new("message", "test-002"))
            .operation_id(Identifier::new("logical-operation", "test-op-002"))
            .payload(serde_json::json!({}))
            .build();

        // Should get an error (404 response can't be parsed as Message)
        let result = client.send("/unknown", &msg).await;
        assert!(result.is_err());

        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_signed_message_roundtrip() {
        let addr = "127.0.0.1:18082";
        let kp = crate::crypto::Ed25519Keypair::generate();
        let public_key = kp.public_key();

        let server = AgentBridgeServer::new();
        server.handle(
            &format!("{}/signed", PATH_PREFIX),
            move |mut msg: Message| {
                // Verify signature if present
                if msg.is_signed() {
                    // In production, verify against known public key
                    // For prototype, just echo back
                }
                msg.msg_type = MessageType::Response;
                msg
            },
        );

        let server_handle = tokio::spawn(async move {
            let _ = server.serve_one(addr).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = AgentBridgeClient::new("http://127.0.0.1:18082");
        let from = Identifier::new("participant", "alice");
        let to = Identifier::new("participant", "bob");

        let mut msg = MessageBuilder::new(from, to)
            .id(Identifier::new("message", "signed-001"))
            .operation_id(Identifier::new("logical-operation", "signed-op-001"))
            .payload(serde_json::json!({"action": "buy", "product_id": "12345"}))
            .build();

        // Sign the message
        msg.sign(&kp).unwrap();
        assert!(msg.is_signed());

        // Send signed message
        let response = client.send("/signed", &msg).await.unwrap();

        assert_eq!(response.msg_type, MessageType::Response);
        assert_eq!(
            response.payload,
            serde_json::json!({"action": "buy", "product_id": "12345"})
        );

        let _ = server_handle.await;
    }
}
