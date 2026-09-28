//! Bounded loopback HTTP/1.1 prototype. JSON transport, CBOR signing. No TLS.
use crate::security::{invalid, valid_endpoint, SecurityPolicy, MAX_BODY, MAX_HEADERS, TIMEOUT};
use crate::{Ed25519PublicKey, Identifier, Message, MessageBuilder, MessageType, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
pub const VERSION_HEADER: &str = "x-ordavyn-version";
pub const PROTOCOL_VERSION: u8 = 2;
pub const PATH_PREFIX: &str = "/ordavyn/v2";
type Handler = Arc<dyn Fn(Message) -> Message + Send + Sync>;
#[derive(Clone)]
pub struct OrdavynServer {
    handlers: Arc<Mutex<HashMap<String, Handler>>>,
    security: Arc<SecurityPolicy>,
}
impl Default for OrdavynServer {
    fn default() -> Self {
        Self::new()
    }
}
impl OrdavynServer {
    pub fn new() -> Self {
        Self::with_policy(Identifier::new("participant", "service"), 10000)
    }
    pub fn with_policy(recipient: Identifier, capacity: usize) -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            security: Arc::new(SecurityPolicy::new(recipient, capacity)),
        }
    }
    pub fn with_journal(
        recipient: Identifier,
        capacity: usize,
        journal: Arc<crate::Journal>,
    ) -> Result<Self> {
        Ok(Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            security: Arc::new(SecurityPolicy::with_journal(recipient, capacity, journal)?),
        })
    }
    pub fn trust(
        &self,
        key: Ed25519PublicKey,
        participant: Identifier,
        actions: &[&str],
    ) -> Result<()> {
        self.security.trust(key, participant, actions)
    }
    pub fn handle<F>(&self, path: &str, handler: F)
    where
        F: Fn(Message) -> Message + Send + Sync + 'static,
    {
        let endpoint = path
            .strip_prefix(PATH_PREFIX)
            .expect("Ordavyn route required");
        assert!(valid_endpoint(endpoint));
        let mut handlers = self.handlers.lock().unwrap();
        assert!(!handlers.contains_key(path), "duplicate route");
        handlers.insert(path.into(), Arc::new(handler));
    }
    /// All direct and HTTP calls pass this gate. Failed actions retain their reservation.
    pub fn dispatch(&self, path: &str, msg: &Message) -> Result<Message> {
        crate::wire::validate(msg, false)?;
        let action = path
            .strip_prefix(&format!("{PATH_PREFIX}/"))
            .ok_or_else(|| invalid("route mismatch"))?;
        if !valid_endpoint(&format!("/{action}")) {
            return Err(invalid("invalid route"));
        }
        let handler = self
            .handlers
            .lock()
            .map_err(|_| invalid("handlers unavailable"))?
            .get(path)
            .cloned()
            .ok_or_else(|| invalid("unknown route"))?;
        let reservation = self.security.authorize_and_reserve(msg, action)?;
        let mut response = MessageBuilder::new(self.security.recipient.clone(), msg.from.clone())
            .operation_id(msg.operation_id.clone())
            .subject(msg.subject.clone())
            .epoch(msg.epoch.clone())
            .build();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(msg.clone()))) {
            Ok(result) => {
                response.msg_type = if result.msg_type == MessageType::Error {
                    MessageType::Error
                } else {
                    MessageType::Response
                };
                response.payload = result.payload;
            }
            Err(_) => {
                response.msg_type = MessageType::Error;
                response.payload = serde_json::json!({"error":"handler failed"});
            }
        }
        crate::wire::validate(&response, false)?;
        if response.msg_type == MessageType::Response {
            reservation.complete()?;
        }
        Ok(response)
    }
    pub async fn serve(&self, addr: &str) -> Result<()> {
        let listener = local_listener(addr).await?;
        loop {
            let (mut socket, _) = listener
                .accept()
                .await
                .map_err(|_| invalid("accept failed"))?;
            // Sequential and bounded: no unbounded task allocation on incoming connections.
            let _ = tokio::time::timeout(TIMEOUT, self.connection(&mut socket)).await;
        }
    }
    pub async fn serve_one(&self, addr: &str) -> Result<()> {
        let listener = local_listener(addr).await?;
        self.serve_listener_one(listener).await
    }
    pub async fn serve_listener_one(&self, listener: TcpListener) -> Result<()> {
        if !listener
            .local_addr()
            .map_err(|_| invalid("listener address"))?
            .ip()
            .is_loopback()
        {
            return Err(invalid("loopback only"));
        }
        tokio::time::timeout(TIMEOUT, async {
            let (mut socket, _) = listener
                .accept()
                .await
                .map_err(|_| invalid("accept failed"))?;
            self.connection(&mut socket).await
        })
        .await
        .map_err(|_| invalid("HTTP deadline"))?
    }
    async fn connection(&self, socket: &mut TcpStream) -> Result<()> {
        let result: Result<Vec<u8>> = async {
            let (line, headers, body) = read_http(socket).await?;
            let parts: Vec<_> = line.split(' ').collect();
            if parts.len() != 3 || parts[0] != "POST" || parts[2] != "HTTP/1.1" {
                return Err(invalid("invalid request line"));
            }
            check_headers(&headers)?;
            let msg: Message = crate::json::message(&body)?;
            let mut response = self.dispatch(parts[1], &msg)?;
            // Dispatch already validated the model. Only the actual JSON byte
            // budget can fail here; retain correlation and the replay reservation.
            let bytes = serde_json::to_vec(&response).map_err(|_| invalid("invalid response"))?;
            if bytes.len() > MAX_BODY {
                response.msg_type = MessageType::Error;
                response.payload = serde_json::json!({"error":"response exceeds HTTP byte limit; effect may have occurred"});
                return crate::wire::to_json(&response);
            }
            Ok(bytes)
        }
        .await;
        let (status, body) = match result {
            Ok(body) => (200, body),
            Err(_) => (403, b"{\"error\":\"request rejected\"}".to_vec()),
        };
        write_http(socket, status, &body).await
    }
}
async fn local_listener(addr: &str) -> Result<TcpListener> {
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|_| invalid("numeric loopback address required"))?;
    if !addr.ip().is_loopback() {
        return Err(invalid("loopback only"));
    }
    TcpListener::bind(addr)
        .await
        .map_err(|_| invalid("bind failed"))
}
fn check_headers(headers: &HashMap<String, String>) -> Result<()> {
    if headers.get(VERSION_HEADER).map(String::as_str) != Some("2")
        || headers.get("content-type").map(String::as_str) != Some(CONTENT_TYPE_JSON)
        || headers.contains_key("transfer-encoding")
    {
        return Err(invalid("invalid HTTP metadata"));
    }
    Ok(())
}
async fn read_http(socket: &mut TcpStream) -> Result<(String, HashMap<String, String>, Vec<u8>)> {
    let mut raw = Vec::new();
    let header_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if raw.len() > MAX_HEADERS {
            return Err(invalid("headers too large"));
        }
        let mut buf = [0u8; 1024];
        let n = socket
            .read(&mut buf)
            .await
            .map_err(|_| invalid("read failed"))?;
        if n == 0 {
            return Err(invalid("truncated headers"));
        }
        raw.extend_from_slice(&buf[..n]);
    };
    if header_end > MAX_HEADERS {
        return Err(invalid("headers too large"));
    }
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| invalid("invalid headers"))?;
    if !head.is_ascii() {
        return Err(invalid("invalid headers"));
    }
    let mut lines = head.split("\r\n");
    let line = lines
        .next()
        .ok_or_else(|| invalid("missing start line"))?
        .to_string();
    let mut headers = HashMap::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or_else(|| invalid("bad header"))?;
        if headers
            .insert(key.to_ascii_lowercase(), value.trim().to_string())
            .is_some()
        {
            return Err(invalid("duplicate header"));
        }
    }
    let length = headers
        .get("content-length")
        .ok_or_else(|| invalid("missing length"))?;
    if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid length"));
    }
    let length: usize = length.parse().map_err(|_| invalid("invalid length"))?;
    if length == 0 || length > MAX_BODY {
        return Err(invalid("body limit"));
    }
    let mut body = raw[header_end + 4..].to_vec();
    if body.len() > length {
        return Err(invalid("extra body bytes"));
    }
    while body.len() < length {
        let mut buf = [0u8; 4096];
        let wanted = std::cmp::min(buf.len(), length - body.len());
        let n = socket
            .read(&mut buf[..wanted])
            .await
            .map_err(|_| invalid("read failed"))?;
        if n == 0 {
            return Err(invalid("truncated body"));
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok((line, headers, body))
}
async fn write_http(socket: &mut TcpStream, status: u16, body: &[u8]) -> Result<()> {
    let head = format!("HTTP/1.1 {status} Result\r\nContent-Type: {CONTENT_TYPE_JSON}\r\n{VERSION_HEADER}: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    socket
        .write_all(head.as_bytes())
        .await
        .map_err(|_| invalid("write failed"))?;
    socket
        .write_all(body)
        .await
        .map_err(|_| invalid("write failed"))
}
pub struct OrdavynClient {
    base_url: String,
}
impl OrdavynClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
    pub async fn send(&self, endpoint: &str, msg: &Message) -> Result<Message> {
        tokio::time::timeout(TIMEOUT, self.send_inner(endpoint, msg))
            .await
            .map_err(|_| invalid("HTTP deadline"))?
    }
    async fn send_inner(&self, endpoint: &str, msg: &Message) -> Result<Message> {
        if !valid_endpoint(endpoint) {
            return Err(invalid("invalid endpoint"));
        }
        let host = self
            .base_url
            .strip_prefix("http://")
            .ok_or_else(|| invalid("HTTP URL required"))?;
        let addr: std::net::SocketAddr = host
            .parse()
            .map_err(|_| invalid("numeric loopback address required"))?;
        if !addr.ip().is_loopback() {
            return Err(invalid("loopback only"));
        }
        let body = crate::wire::to_json(msg).map_err(|_| invalid("serialization"))?;
        if body.len() > MAX_BODY {
            return Err(invalid("body limit"));
        }
        let mut socket = TcpStream::connect(addr)
            .await
            .map_err(|_| invalid("connect failed"))?;
        let header = format!("POST {PATH_PREFIX}{endpoint} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {CONTENT_TYPE_JSON}\r\n{VERSION_HEADER}: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        socket
            .write_all(header.as_bytes())
            .await
            .map_err(|_| invalid("write failed"))?;
        socket
            .write_all(&body)
            .await
            .map_err(|_| invalid("write failed"))?;
        let (line, headers, body) = read_http(&mut socket).await?;
        check_headers(&headers)?;
        if !line.starts_with("HTTP/1.1 200 ") {
            return Err(invalid("HTTP request rejected"));
        }
        let result: Message = crate::json::message(&body)?;
        if result.version != 2
            || result.encoding != crate::wire::ENCODING
            || !matches!(result.msg_type, MessageType::Response | MessageType::Error)
            || result.from != msg.to
            || result.to != msg.from
            || result.operation_id != msg.operation_id
            || result.subject != msg.subject
            || result.epoch != msg.epoch
            || result.signature.is_some()
            || result.key_id.is_some()
            || result.signature_alg.is_some()
        {
            return Err(invalid("invalid response envelope"));
        }
        Ok(result)
    }
}
