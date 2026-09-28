//! Bounded loopback HTTP/1.1 prototype. JSON transport, CBOR signing. TLS 1.3 is explicit.
use crate::security::{invalid, valid_endpoint, SecurityPolicy, MAX_BODY, MAX_HEADERS, TIMEOUT};
use crate::{Ed25519PublicKey, Identifier, Message, MessageBuilder, MessageType, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
use tokio::net::{TcpListener, TcpStream};
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
pub const VERSION_HEADER: &str = "x-ordavyn-version";
pub const PROTOCOL_VERSION: u8 = 3;
pub const PATH_PREFIX: &str = "/ordavyn/v3";
type Handler = Arc<dyn Fn(Message) -> Message + Send + Sync>;
#[derive(Clone)]
pub struct OrdavynServer {
    handlers: Arc<Mutex<HashMap<String, Handler>>>,
    security: Arc<SecurityPolicy>,
    signer: Option<Arc<crate::Ed25519Keypair>>,
    tls: Option<crate::ServerTls>,
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
            signer: None,
            tls: None,
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
            signer: None,
            tls: None,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            security: Arc::new(SecurityPolicy::with_journal(recipient, capacity, journal)?),
        })
    }
    /// Configure before cloning or using the server; changes require a new object.
    pub fn with_signer(mut self, signer: crate::Ed25519Keypair) -> Self {
        assert_eq!(
            Arc::strong_count(&self.security),
            1,
            "configure before cloning"
        );
        assert!(self.signer.is_none(), "signer is immutable");
        self.signer = Some(Arc::new(signer));
        self
    }
    pub fn with_tls(mut self, tls: crate::ServerTls) -> Self {
        assert_eq!(
            Arc::strong_count(&self.security),
            1,
            "configure before cloning"
        );
        assert!(self.tls.is_none(), "TLS is immutable");
        self.tls = Some(tls);
        self
    }
    pub fn response_key(&self) -> Result<Ed25519PublicKey> {
        Ok(self
            .signer
            .as_ref()
            .ok_or_else(|| invalid("server signer required"))?
            .public_key())
    }
    pub fn trust(
        &self,
        key: Ed25519PublicKey,
        participant: Identifier,
        actions: &[&str],
    ) -> Result<()> {
        self.security.trust(key, participant, actions)
    }
    pub fn revoke(&self, key: &Ed25519PublicKey) -> Result<bool> {
        self.security.revoke(key)
    }
    pub fn rotate_key(&self, old: &Ed25519PublicKey, new: Ed25519PublicKey) -> Result<()> {
        self.security.rotate_key(old, new)
    }
    pub fn request_stop(&self) {
        self.security.request_stop();
    }
    /// A timeout does not cancel an admitted handler. Call again to await completion.
    pub async fn stop(&self, timeout: std::time::Duration) -> bool {
        self.security.stop(timeout).await
    }
    pub fn resume(&self) -> Result<()> {
        self.security.resume()
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
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| invalid("server signer required"))?;
        crate::wire::validate(msg, false)?;
        if msg.msg_type != MessageType::Request || msg.to != self.security.recipient {
            return Err(invalid("invalid request recipient or type"));
        }
        let digest = crate::wire::request_digest(msg)?;
        let mut response = MessageBuilder::new(self.security.recipient.clone(), msg.from.clone())
            .operation_id(msg.operation_id.clone())
            .subject(msg.subject.clone())
            .epoch(msg.epoch.clone())
            .build();
        response.reply_to = Some(msg.id.clone());
        response.request_digest = Some(digest);
        // Keep admission owned through signing and both serialization budgets.
        let mut reservation = None;
        let outcome: Result<()> = (|| {
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
            reservation = Some(self.security.authorize_and_reserve(msg, action)?);
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(msg.clone())))
                    .map_err(|_| invalid("handler failed; outcome may be unknown"))?;
            response.msg_type = if result.msg_type == MessageType::Error {
                MessageType::Error
            } else {
                MessageType::Response
            };
            response.payload = result.payload;
            response.sign(signer)?;
            crate::wire::to_json(&response)?;
            if response.msg_type == MessageType::Response {
                reservation.as_ref().unwrap().complete()?;
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            response.msg_type = MessageType::Error;
            response.payload =
                serde_json::json!({"error": format!("{error}; effect may have occurred")});
            response.sign(signer)?;
            crate::wire::to_json(&response)?;
        }
        Ok(response)
    }
    pub async fn serve(&self, addr: &str) -> Result<()> {
        let work = self.security.begin_listener()?;
        let listener = local_listener(addr).await?;
        self.security.open_listener(&work)?;
        loop {
            tokio::select! {
                biased;
                _ = self.security.stopped() => return Ok(()),
                result = listener.accept() => {
                    let (mut socket, _) = result.map_err(|_| invalid("accept failed"))?;
                    // Await one worker before accepting another connection. Cancellation
                    // leaves its independent accounting alive until the worker exits.
                    tokio::select! {
                        biased;
                        _ = self.security.stopped() => return Ok(()),
                        _ = self.accept_connection(&mut socket, tokio::time::Instant::now() + TIMEOUT) => {}
                    }
                }
            }
        }
    }
    pub async fn serve_one(&self, addr: &str) -> Result<()> {
        let work = self.security.begin_listener()?;
        let listener = local_listener(addr).await?;
        self.security.open_listener(&work)?;
        self.listener_one(listener).await
    }
    pub async fn serve_listener_one(&self, listener: TcpListener) -> Result<()> {
        let work = self.security.begin_listener()?;
        if !listener
            .local_addr()
            .map_err(|_| invalid("listener address"))?
            .ip()
            .is_loopback()
        {
            return Err(invalid("loopback only"));
        }
        self.security.open_listener(&work)?;
        self.listener_one(listener).await
    }
    async fn listener_one(&self, listener: TcpListener) -> Result<()> {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        tokio::select! {
            biased;
            _ = self.security.stopped() => Ok(()),
            result = async {
                let (mut socket, _) = tokio::time::timeout_at(deadline, listener.accept())
                    .await.map_err(|_| invalid("HTTP deadline"))?
                    .map_err(|_| invalid("accept failed"))?;
                self.accept_connection(&mut socket, deadline).await
            } => result
        }
    }
    async fn accept_connection(
        &self,
        socket: &mut TcpStream,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        if let Some(tls) = &self.tls {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.config.clone());
            let mut stream = tokio::time::timeout_at(deadline, acceptor.accept(socket))
                .await
                .map_err(|_| invalid("TLS deadline"))?
                .map_err(|_| invalid("TLS handshake failed"))?;
            if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1") {
                return Err(invalid("TLS ALPN mismatch"));
            }
            self.connection(&mut stream, deadline).await
        } else {
            self.connection(socket, deadline).await
        }
    }
    async fn connection(
        &self,
        socket: &mut impl Stream,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        // A network deadline closes the connection without a fresh error-write
        // interval. The I/O deadline does not cancel the sole dispatch worker:
        // awaiting it retains this connection until completion or stop/cancellation.
        // Independent worker accounting remains alive after network cancellation.
        let input = tokio::time::timeout_at(deadline, read_http(socket))
            .await
            .map_err(|_| invalid("HTTP deadline"))?;
        let result: Result<Vec<u8>> = async {
            let (line, headers, body) = input?;
            let parts: Vec<_> = line.split(' ').collect();
            if parts.len() != 3 || parts[0] != "POST" || parts[2] != "HTTP/1.1" {
                return Err(invalid("invalid request line"));
            }
            check_headers(&headers)?;
            let msg: Message = crate::json::message(&body)?;
            let path = parts[1].to_owned();
            let server = self.clone();
            let work = self.security.begin_worker()?;
            let response = tokio::task::spawn_blocking(move || {
                let _work = work;
                server.dispatch(&path, &msg)
            })
            .await
            .map_err(|_| invalid("dispatch worker failed"))??;
            crate::wire::to_json(&response)
        }
        .await;
        if tokio::time::Instant::now() >= deadline {
            return Err(invalid("HTTP deadline"));
        }
        let (status, body) = match result {
            Ok(body) => (200, body),
            Err(_) => (403, b"{\"error\":\"request rejected\"}".to_vec()),
        };
        tokio::time::timeout_at(deadline, write_http(socket, status, &body))
            .await
            .map_err(|_| invalid("HTTP deadline"))?
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
    if headers.get(VERSION_HEADER).map(String::as_str) != Some("3")
        || headers.get("content-type").map(String::as_str) != Some(CONTENT_TYPE_JSON)
        || headers.contains_key("transfer-encoding")
    {
        return Err(invalid("invalid HTTP metadata"));
    }
    Ok(())
}
async fn read_http(
    socket: &mut (impl Stream + ?Sized),
) -> Result<(String, HashMap<String, String>, Vec<u8>)> {
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
async fn write_http(socket: &mut (impl Stream + ?Sized), status: u16, body: &[u8]) -> Result<()> {
    let head = format!("HTTP/1.1 {status} Result\r\nContent-Type: {CONTENT_TYPE_JSON}\r\n{VERSION_HEADER}: 3\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
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
    pin: Option<(Ed25519PublicKey, Identifier)>,
    tls: Option<crate::ClientTls>,
}
impl OrdavynClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.into(),
            pin: None,
            tls: None,
        }
    }
    pub fn with_response_key(mut self, key: Ed25519PublicKey, participant: Identifier) -> Self {
        self.pin = Some((key, participant));
        self
    }
    pub fn with_tls(mut self, tls: crate::ClientTls) -> Self {
        self.tls = Some(tls);
        self
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
        let (pin_key, participant) = self
            .pin
            .as_ref()
            .ok_or_else(|| invalid("local response pin required"))?;
        if participant != &msg.to
            || participant.namespace != "participant"
            || !participant.is_valid()
        {
            return Err(invalid("response participant mismatch"));
        }
        let digest = crate::wire::request_digest(msg)?;
        let scheme = if self.tls.is_some() {
            "https://"
        } else {
            "http://"
        };
        let host = self
            .base_url
            .strip_prefix(scheme)
            .ok_or_else(|| invalid("transport configuration mismatch"))?;
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
        let socket = TcpStream::connect(addr)
            .await
            .map_err(|_| invalid("connect failed"))?;
        let mut socket: Box<dyn Stream> = if let Some(tls) = &self.tls {
            let stream = tokio_rustls::TlsConnector::from(tls.config.clone())
                .connect(tls.name.clone(), socket)
                .await
                .map_err(|_| invalid("TLS handshake failed"))?;
            if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1") {
                return Err(invalid("TLS ALPN mismatch"));
            }
            Box::new(stream)
        } else {
            Box::new(socket)
        };
        let header = format!("POST {PATH_PREFIX}{endpoint} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {CONTENT_TYPE_JSON}\r\n{VERSION_HEADER}: 3\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
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
        if result.version != 3
            || result.encoding != crate::wire::ENCODING
            || !matches!(result.msg_type, MessageType::Response | MessageType::Error)
            || result.from != msg.to
            || result.to != msg.from
            || result.operation_id != msg.operation_id
            || result.subject != msg.subject
            || result.epoch != msg.epoch
            || result.reply_to.as_ref() != Some(&msg.id)
            || result.request_digest.as_ref() != Some(&digest)
            || &result.from != participant
            || result.verify_signature(pin_key).is_err()
        {
            return Err(invalid("invalid response envelope"));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    struct PoolGate {
        open: Mutex<bool>,
        changed: Condvar,
    }
    impl PoolGate {
        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }
    struct ReleaseOnDrop(Arc<PoolGate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[test]
    fn cancelled_serve_keeps_queued_worker_owned() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let gate = Arc::new(PoolGate {
                open: Mutex::new(false),
                changed: Condvar::new(),
            });
            let _release_on_exit = ReleaseOnDrop(gate.clone());
            let (occupied_tx, occupied_rx) = tokio::sync::oneshot::channel();
            let worker_gate = gate.clone();
            let occupied = tokio::task::spawn_blocking(move || {
                occupied_tx.send(()).unwrap();
                let open = worker_gate.open.lock().unwrap();
                let (open, _) = worker_gate
                    .changed
                    .wait_timeout_while(open, Duration::from_secs(5), |v| !*v)
                    .unwrap();
                assert!(*open, "blocking pool release deadline");
            });
            tokio::time::timeout(Duration::from_secs(3), occupied_rx)
                .await
                .unwrap()
                .unwrap();
            let server =
                OrdavynServer::new().with_signer(crate::Ed25519Keypair::from_seed([99; 32]));
            let key = crate::Ed25519Keypair::generate();
            server
                .trust(
                    key.public_key(),
                    Identifier::new("participant", "caller"),
                    &["act"],
                )
                .unwrap();
            server.handle("/ordavyn/v3/act", |_| {
                panic!("stopped queued work was admitted")
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let clone = server.clone();
            let serving = tokio::spawn(async move { clone.serve_listener_one(listener).await });
            let mut request = MessageBuilder::new(
                Identifier::new("participant", "caller"),
                Identifier::new("participant", "service"),
            )
            .payload(serde_json::json!({"action":"act"}))
            .build();
            request.sign(&key).unwrap();
            let client = tokio::spawn(async move {
                OrdavynClient::new(&format!("http://{address}"))
                    .with_response_key(
                        crate::Ed25519Keypair::from_seed([99; 32]).public_key(),
                        crate::Identifier::new("participant", "service"),
                    )
                    .send("/act", &request)
                    .await
            });
            // The only blocking thread is held above. Two owned network units
            // prove the listener parsed the request and queued its worker.
            tokio::time::timeout(Duration::from_secs(3), async {
                while server.security.network_work_count() != 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            serving.abort();
            assert!(tokio::time::timeout(Duration::from_secs(3), serving)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled());
            assert_eq!(server.security.network_work_count(), 1);
            assert!(!server.stop(Duration::ZERO).await);
            assert!(server.resume().is_err());
            assert!(server.serve_one("127.0.0.1:0").await.is_err());
            assert!(server.security.journal.inspect().unwrap().is_empty());
            gate.release();
            tokio::time::timeout(Duration::from_secs(3), occupied)
                .await
                .unwrap()
                .unwrap();
            assert!(server.stop(Duration::from_secs(3)).await);
            assert_eq!(server.security.network_work_count(), 0);
            assert!(server.security.journal.inspect().unwrap().is_empty());
            server.resume().unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(3), client)
                .await
                .unwrap();
        });
    }
}
