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
    accepting: bool,
    active: usize,
    network: usize,
    generation: u64,
}
pub struct SecurityPolicy {
    pub recipient: Identifier,
    pub journal: Arc<Journal>,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
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
                accepting: true,
                active: 0,
                network: 0,
                generation: 0,
            }),
            changed: tokio::sync::Notify::new(),
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if let Some(old) = state.grants.get(&key.key_id()) {
            if old.key != key || old.participant != grant.participant {
                return Err(invalid("conflicting local key binding"));
            }
        }
        state.grants.insert(key.key_id(), grant);
        Ok(())
    }
    pub fn revoke(&self, key: &Ed25519PublicKey) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if state
            .grants
            .get(&key.key_id())
            .is_some_and(|g| &g.key == key)
        {
            state.grants.remove(&key.key_id());
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub fn rotate_key(&self, old: &Ed25519PublicKey, new: Ed25519PublicKey) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if old == &new
            || state.grants.contains_key(&new.key_id())
            || !state
                .grants
                .get(&old.key_id())
                .is_some_and(|g| &g.key == old)
        {
            return Err(invalid("invalid key rotation"));
        }
        let mut grant = state.grants.remove(&old.key_id()).expect("checked grant");
        grant.key = new.clone();
        state.grants.insert(new.key_id(), grant);
        Ok(())
    }
    pub fn request_stop(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.accepting = false;
        state.generation = state.generation.wrapping_add(1);
        self.changed.notify_waiters();
    }
    pub fn resume(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if state.active != 0 || state.network != 0 {
            return Err(invalid("work still running"));
        }
        state.accepting = true;
        Ok(())
    }
    pub async fn stop(&self, timeout: std::time::Duration) -> bool {
        assert!(
            std::time::Instant::now().checked_add(timeout).is_some(),
            "timeout out of range"
        );
        self.request_stop();
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .expect("validated timeout");
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.active == 0 && state.network == 0 {
                    return true;
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn network_work_count(&self) -> usize {
        self.state.lock().unwrap().network
    }
    pub(crate) fn begin_listener(self: &Arc<Self>) -> Result<NetworkWork> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if state.network != 0 || (!state.accepting && state.active != 0) {
            return Err(invalid("server or handler still running"));
        }
        state.network += 1;
        Ok(NetworkWork {
            policy: self.clone(),
            generation: state.generation,
        })
    }
    pub(crate) fn open_listener(&self, work: &NetworkWork) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if state.generation != work.generation {
            return Err(invalid("admission stopped"));
        }
        state.accepting = true;
        Ok(())
    }
    pub(crate) fn begin_worker(self: &Arc<Self>) -> Result<NetworkWork> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if !state.accepting {
            return Err(invalid("admission stopped"));
        }
        state.network += 1;
        Ok(NetworkWork {
            policy: self.clone(),
            generation: state.generation,
        })
    }
    pub(crate) async fn stopped(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .accepting
            {
                return;
            }
            notified.await;
        }
    }
    pub fn authorize_and_reserve(&self, msg: &Message, action: &str) -> Result<Admission<'_>> {
        crate::wire::validate(msg, false)?;
        if msg.version != 3
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("security state unavailable"))?;
        if !state.accepting {
            return Err(invalid("admission stopped"));
        }
        let grant = state
            .grants
            .get(msg.key_id.as_deref().unwrap_or(""))
            .ok_or_else(|| invalid("untrusted key"))?;
        if grant.participant != msg.from || !grant.actions.contains(action) {
            return Err(invalid("not authorized"));
        }
        msg.verify_signature(&grant.key)?;
        let reservation = self
            .journal
            .reserve(&msg.from, &msg.id, &msg.operation_id)?;
        state.active += 1;
        Ok(Admission {
            policy: self,
            reservation: Some(reservation),
        })
    }
}

/// Owns both replay reservation and admission lifetime, including unwinding.
pub struct Admission<'a> {
    policy: &'a SecurityPolicy,
    reservation: Option<Reservation>,
}
impl Admission<'_> {
    pub fn complete(&self) -> Result<()> {
        self.reservation
            .as_ref()
            .expect("live reservation")
            .complete()
    }
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        // Release journal activity before announcing quiescence.
        drop(self.reservation.take());
        let mut state = self.policy.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        self.policy.changed.notify_waiters();
    }
}
pub(crate) struct NetworkWork {
    policy: Arc<SecurityPolicy>,
    generation: u64,
}
impl Drop for NetworkWork {
    fn drop(&mut self) {
        let mut state = self.policy.state.lock().unwrap_or_else(|e| e.into_inner());
        state.network -= 1;
        self.policy.changed.notify_waiters();
    }
}
