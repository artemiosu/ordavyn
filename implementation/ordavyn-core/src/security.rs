//! Explicit local grants and atomic local replay reservation. No eviction.
use crate::journal::{Journal, Reservation};
use crate::{CoreError, Ed25519PublicKey, Identifier, Message, MessageType, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
pub const MAX_BODY: usize = 65536;
pub const MAX_HEADERS: usize = 8192;
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
struct Grant {
    key: Ed25519PublicKey,
    participant: Identifier,
    actions: HashSet<String>,
}
struct State {
    grants: HashMap<String, Grant>,
}
pub struct SecurityPolicy {
    pub recipient: Identifier,
    pub journal: Arc<Journal>,
    state: Mutex<State>,
}
pub fn invalid(reason: &str) -> CoreError {
    CoreError::InvalidMessage(reason.into())
}
pub fn valid_endpoint(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && !path.ends_with('/')
        && !path.contains("//")
        && path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/_-".contains(&c))
}
impl SecurityPolicy {
    pub fn new(recipient: Identifier, capacity: usize) -> Self {
        assert!(recipient.namespace == "participant" && recipient.is_valid() && capacity > 0);
        Self::with_journal(
            recipient.clone(),
            capacity,
            Arc::new(Journal::memory(recipient, capacity).expect("valid journal")),
        )
        .expect("valid binding")
    }
    pub fn with_journal(
        recipient: Identifier,
        capacity: usize,
        journal: Arc<Journal>,
    ) -> Result<Self> {
        if journal.recipient() != &recipient || journal.capacity() != capacity {
            return Err(invalid("journal binding mismatch"));
        }
        Ok(Self {
            recipient,
            journal,
            state: Mutex::new(State {
                grants: HashMap::new(),
            }),
        })
    }
    pub fn trust(
        &self,
        key: Ed25519PublicKey,
        participant: Identifier,
        actions: &[&str],
    ) -> Result<()> {
        if participant.namespace != "participant"
            || !participant.is_valid()
            || actions.is_empty()
            || actions.iter().any(|a| !valid_endpoint(&format!("/{a}")))
        {
            return Err(invalid("invalid local key binding"));
        }
        let grant = Grant {
            key: key.clone(),
            participant,
            actions: actions.iter().map(|s| s.to_string()).collect(),
        };
        self.state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?
            .grants
            .insert(key.key_id(), grant);
        Ok(())
    }
    pub fn authorize_and_reserve(&self, msg: &Message, action: &str) -> Result<Reservation> {
        crate::wire::validate(msg, false)?;
        if msg.version != 2
            || msg.msg_type != MessageType::Request
            || msg.encoding != crate::wire::ENCODING
            || msg.to != self.recipient
            || msg.from.namespace != "participant"
            || msg.id.namespace != "message"
            || msg.operation_id.namespace != "logical-operation"
            || msg.epoch.namespace != "epoch"
            || msg.payload.get("action").and_then(|v| v.as_str()) != Some(action)
        {
            return Err(invalid("invalid envelope or route"));
        }
        if msg.subject.target_type.is_empty() || msg.subject.target_type.len() > 256 {
            return Err(invalid("invalid subject metadata"));
        }
        for id in [
            &msg.id,
            &msg.operation_id,
            &msg.from,
            &msg.to,
            &msg.epoch,
            &msg.subject.target_id,
        ] {
            if !id.is_valid() || id.value.len() > 256 || id.namespace.len() > 256 {
                return Err(invalid("invalid identifier"));
            }
        }
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        let grant = state
            .grants
            .get(msg.key_id.as_deref().unwrap_or(""))
            .ok_or_else(|| invalid("untrusted key"))?;
        if grant.participant != msg.from || !grant.actions.contains(action) {
            return Err(invalid("not authorized"));
        }
        msg.verify_signature(&grant.key)?;
        self.journal.reserve(&msg.from, &msg.id, &msg.operation_id)
    }
}
