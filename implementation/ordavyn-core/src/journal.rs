//! Local replay reservation. SQLite is an optional local adapter, never a wire contract.
use crate::{security::invalid, Identifier, Result};
use rusqlite::{params, Connection, OpenFlags};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

const METADATA_SCHEMA: &str = "CREATE TABLE metadata(version INTEGER NOT NULL, recipient BLOB NOT NULL, capacity INTEGER NOT NULL)";
const OPERATIONS_SCHEMA: &str = "CREATE TABLE operations(sender BLOB NOT NULL, message BLOB NOT NULL, operation BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('outcome_unknown','handler_returned')), UNIQUE(sender,message), UNIQUE(sender,operation))";

type Key = (Vec<u8>, Vec<u8>, Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    OutcomeUnknown,
    HandlerReturned,
}
#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub sender: Identifier,
    pub message: Identifier,
    pub operation: Identifier,
    pub state: Outcome,
}
#[derive(Default)]
struct MemoryState {
    rows: HashMap<Key, Outcome>,
    messages: HashSet<(Vec<u8>, Vec<u8>)>,
    operations: HashSet<(Vec<u8>, Vec<u8>)>,
}
enum Backend {
    Memory(MemoryState),
    SQLite(Connection),
}
struct State {
    backend: Option<Backend>,
    active: HashSet<Key>,
}
pub struct Journal {
    recipient: Identifier,
    capacity: usize,
    state: Mutex<State>,
}
/// The guard prevents close during a handler, including unwinding. Dropping never unreserves.
pub struct Reservation {
    journal: Arc<Journal>,
    key: Key,
}
impl Reservation {
    pub fn complete(&self) -> Result<()> {
        self.journal.complete(&self.key)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.journal.state.lock() {
            state.active.remove(&self.key);
        }
    }
}
fn storage<E: std::fmt::Display>(e: E) -> crate::CoreError {
    invalid(&format!("journal storage: {e}"))
}
pub fn identifier_blob(id: &Identifier) -> Result<Vec<u8>> {
    if !id.is_valid() || id.namespace.len() > 256 || id.value.len() > 256 {
        return Err(invalid("invalid journal identifier"));
    }
    let value = ciborium::Value::Array(vec![
        ciborium::Value::Text(id.namespace.clone()),
        ciborium::Value::Text(id.value.clone()),
        id.version
            .map(|v| ciborium::Value::Integer(v.into()))
            .unwrap_or(ciborium::Value::Null),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).map_err(storage)?;
    Ok(bytes)
}
fn decode(blob: &[u8], namespace: &str) -> Result<Identifier> {
    let value: ciborium::Value = ciborium::de::from_reader(blob).map_err(storage)?;
    let ciborium::Value::Array(parts) = value else {
        return Err(invalid("invalid journal identifier"));
    };
    if parts.len() != 3 {
        return Err(invalid("invalid journal identifier"));
    }
    let (ciborium::Value::Text(ns), ciborium::Value::Text(value)) = (&parts[0], &parts[1]) else {
        return Err(invalid("invalid journal identifier"));
    };
    let version = match &parts[2] {
        ciborium::Value::Null => None,
        ciborium::Value::Integer(i) => Some(u64::try_from(*i).map_err(storage)?),
        _ => return Err(invalid("invalid journal version")),
    };
    let id = Identifier {
        namespace: ns.clone(),
        value: value.clone(),
        version,
    };
    if ns != namespace || identifier_blob(&id)? != blob {
        return Err(invalid("invalid journal identifier"));
    }
    Ok(id)
}
fn entries(db: &Connection) -> Result<Vec<JournalEntry>> {
    let mut stmt = db
        .prepare("SELECT sender,message,operation,state FROM operations")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(storage)?;
    rows.map(|row| {
        let (a, b, c, d) = row.map_err(storage)?;
        Ok(JournalEntry {
            sender: decode(&a, "participant")?,
            message: decode(&b, "message")?,
            operation: decode(&c, "logical-operation")?,
            state: match d.as_str() {
                "outcome_unknown" => Outcome::OutcomeUnknown,
                "handler_returned" => Outcome::HandlerReturned,
                _ => return Err(invalid("unknown journal state")),
            },
        })
    })
    .collect()
}
impl Journal {
    fn build(recipient: Identifier, capacity: usize, backend: Backend) -> Result<Self> {
        identifier_blob(&recipient)?;
        if recipient.namespace != "participant" || capacity == 0 || capacity > i64::MAX as usize {
            return Err(invalid("recipient and positive capacity required"));
        }
        Ok(Self {
            recipient,
            capacity,
            state: Mutex::new(State {
                backend: Some(backend),
                active: HashSet::new(),
            }),
        })
    }
    /// Explicitly temporary. Restart loses all reservations.
    pub fn memory(recipient: Identifier, capacity: usize) -> Result<Self> {
        Self::build(recipient, capacity, Backend::Memory(MemoryState::default()))
    }
    pub fn create(path: impl AsRef<Path>, recipient: Identifier, capacity: usize) -> Result<Self> {
        Self::sqlite(path.as_ref(), recipient, capacity, true)
    }
    pub fn open(path: impl AsRef<Path>, recipient: Identifier, capacity: usize) -> Result<Self> {
        Self::sqlite(path.as_ref(), recipient, capacity, false)
    }
    fn sqlite(path: &Path, recipient: Identifier, capacity: usize, create: bool) -> Result<Self> {
        // Validate before creating any file; never unlink a failed creation or reset a journal.
        let mut journal = Self::memory(recipient, capacity)?;
        if create {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).map_err(storage)?;
        }
        if !std::fs::symlink_metadata(path)
            .map_err(storage)?
            .file_type()
            .is_file()
        {
            return Err(invalid("ordinary local file required"));
        }
        let mut db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        db.busy_timeout(Duration::from_secs(3)).map_err(storage)?;
        let mode: String = db
            .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
            .map_err(storage)?;
        db.execute_batch("PRAGMA synchronous=EXTRA")
            .map_err(storage)?;
        let sync: i64 = db
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .map_err(storage)?;
        let timeout: i64 = db
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .map_err(storage)?;
        if mode != "delete" || sync != 3 || timeout != 3000 {
            return Err(invalid("journal durability settings unavailable"));
        }
        if create {
            let tx = db
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(storage)?;
            tx.execute_batch(METADATA_SCHEMA).map_err(storage)?;
            tx.execute_batch(OPERATIONS_SCHEMA).map_err(storage)?;
            tx.execute(
                "INSERT INTO metadata VALUES (1,?,?)",
                params![identifier_blob(&journal.recipient)?, capacity as i64],
            )
            .map_err(storage)?;
            tx.commit().map_err(storage)?;
        }
        Self::validate(&mut db, &journal.recipient, capacity)?;
        journal.state.get_mut().map_err(storage)?.backend = Some(Backend::SQLite(db));
        Ok(journal)
    }
    fn validate(db: &mut Connection, recipient: &Identifier, capacity: usize) -> Result<()> {
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        let integrity: String = tx
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(storage)?;
        if integrity != "ok" {
            return Err(invalid("corrupt journal"));
        }
        {
            let mut stmt = tx.prepare("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").map_err(storage)?;
            let objects: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(storage)?
                .collect::<std::result::Result<_, _>>()
                .map_err(storage)?;
            if objects
                != vec![
                    ("table".into(), "metadata".into()),
                    ("table".into(), "operations".into()),
                ]
            {
                return Err(invalid("unknown journal schema"));
            }
        }
        for (name, expected) in [
            ("metadata", METADATA_SCHEMA),
            ("operations", OPERATIONS_SCHEMA),
        ] {
            let sql: String = tx
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    [name],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if sql != expected {
                return Err(invalid("unknown journal table definition"));
            }
        }
        for (table, names) in [
            (
                "metadata",
                vec![
                    ("version", "INTEGER"),
                    ("recipient", "BLOB"),
                    ("capacity", "INTEGER"),
                ],
            ),
            (
                "operations",
                vec![
                    ("sender", "BLOB"),
                    ("message", "BLOB"),
                    ("operation", "BLOB"),
                    ("state", "TEXT"),
                ],
            ),
        ] {
            let mut stmt = tx
                .prepare(&format!("PRAGMA table_info({table})"))
                .map_err(storage)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?;
            if rows.len() != names.len()
                || rows
                    .iter()
                    .zip(names)
                    .any(|(r, n)| r.0 != n.0 || r.1 != n.1 || r.2 != 1 || r.3.is_some() || r.4 != 0)
            {
                return Err(invalid("unknown journal columns"));
            }
        }
        {
            let mut stmt = tx
                .prepare("PRAGMA index_list(operations)")
                .map_err(storage)?;
            let indexes = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                })
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?;
            if indexes.len() != 2 || indexes.iter().any(|r| r.1 != 1 || r.2 != "u" || r.3 != 0) {
                return Err(invalid("journal uniqueness missing"));
            }
            let mut columns = Vec::new();
            for row in indexes {
                let mut stmt = tx
                    .prepare("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
                    .map_err(storage)?;
                columns.push(
                    stmt.query_map([row.0], |r| r.get::<_, String>(0))
                        .map_err(storage)?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(storage)?,
                );
            }
            columns.sort();
            if columns != vec![vec!["sender", "message"], vec!["sender", "operation"]] {
                return Err(invalid("invalid journal indexes"));
            }
        }
        {
            let mut stmt = tx
                .prepare("SELECT version,recipient,capacity FROM metadata")
                .map_err(storage)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?;
            if rows != vec![(1, identifier_blob(recipient)?, capacity as i64)] {
                return Err(invalid("journal metadata mismatch"));
            }
        }
        if entries(&tx)?.len() > capacity {
            return Err(invalid("journal over capacity"));
        }
        tx.commit().map_err(storage)
    }
    pub fn recipient(&self) -> &Identifier {
        &self.recipient
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn reserve(
        self: &Arc<Self>,
        sender: &Identifier,
        message: &Identifier,
        operation: &Identifier,
    ) -> Result<Reservation> {
        let key = (
            identifier_blob(sender)?,
            identifier_blob(message)?,
            identifier_blob(operation)?,
        );
        decode(&key.0, "participant")?;
        decode(&key.1, "message")?;
        decode(&key.2, "logical-operation")?;
        let mut state = self.state.lock().map_err(storage)?;
        match state
            .backend
            .as_mut()
            .ok_or_else(|| invalid("journal closed"))?
        {
            Backend::Memory(memory) => {
                if memory.messages.contains(&(key.0.clone(), key.1.clone()))
                    || memory.operations.contains(&(key.0.clone(), key.2.clone()))
                {
                    return Err(invalid("replay"));
                }
                if memory.rows.len() >= self.capacity {
                    return Err(invalid("replay journal full"));
                }
                memory.rows.insert(key.clone(), Outcome::OutcomeUnknown);
                memory.messages.insert((key.0.clone(), key.1.clone()));
                memory.operations.insert((key.0.clone(), key.2.clone()));
            }
            Backend::SQLite(db) => {
                let tx = db
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(storage)?;
                let replay: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE sender=? AND (message=? OR operation=?))", params![key.0,key.1,key.2], |r| r.get(0)).map_err(storage)?;
                if replay {
                    return Err(invalid("replay"));
                }
                let count: i64 = tx
                    .query_row("SELECT count(*) FROM operations", [], |r| r.get(0))
                    .map_err(storage)?;
                if count >= self.capacity as i64 {
                    return Err(invalid("replay journal full"));
                }
                tx.execute(
                    "INSERT INTO operations VALUES (?,?,?,'outcome_unknown')",
                    params![key.0, key.1, key.2],
                )
                .map_err(storage)?;
                tx.commit().map_err(storage)?;
            }
        }
        state.active.insert(key.clone());
        Ok(Reservation {
            journal: self.clone(),
            key,
        })
    }
    fn complete(&self, key: &Key) -> Result<()> {
        let mut state = self.state.lock().map_err(storage)?;
        if !state.active.contains(key) {
            return Err(invalid("not an active reservation"));
        }
        match state
            .backend
            .as_mut()
            .ok_or_else(|| invalid("journal closed"))?
        {
            Backend::Memory(memory) => {
                let value = memory
                    .rows
                    .get_mut(key)
                    .ok_or_else(|| invalid("reservation missing"))?;
                if *value != Outcome::OutcomeUnknown {
                    return Err(invalid("already completed"));
                }
                *value = Outcome::HandlerReturned;
            }
            Backend::SQLite(db) => {
                let tx = db
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(storage)?;
                if tx.execute("UPDATE operations SET state='handler_returned' WHERE sender=? AND message=? AND operation=? AND state='outcome_unknown'",params![key.0,key.1,key.2]).map_err(storage)? != 1 { return Err(invalid("reservation missing or completed")); }
                tx.commit().map_err(storage)?;
            }
        }
        Ok(())
    }
    pub fn inspect(&self) -> Result<Vec<JournalEntry>> {
        let state = self.state.lock().map_err(storage)?;
        match state
            .backend
            .as_ref()
            .ok_or_else(|| invalid("journal closed"))?
        {
            Backend::Memory(memory) => memory
                .rows
                .iter()
                .map(|(k, v)| {
                    Ok(JournalEntry {
                        sender: decode(&k.0, "participant")?,
                        message: decode(&k.1, "message")?,
                        operation: decode(&k.2, "logical-operation")?,
                        state: v.clone(),
                    })
                })
                .collect(),
            Backend::SQLite(db) => entries(db),
        }
    }
    pub fn close(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(storage)?;
        if !state.active.is_empty() {
            return Err(invalid("handler still active"));
        }
        if let Some(Backend::SQLite(db)) = state.backend.take() {
            if let Err((db, e)) = db.close() {
                state.backend = Some(Backend::SQLite(db));
                return Err(storage(e));
            }
        }
        Ok(())
    }
}
