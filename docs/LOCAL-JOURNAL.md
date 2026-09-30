# Local replay journal

Both SDKs can explicitly select a persistent SQLite journal. The default memory
journal is temporary: losing that object or restarting the process loses its replay
protection. SQLite is a replaceable local storage adapter, not a wire-envelope extension.
Signature, participant, recipient, action and exact-route checks precede reservation.
No payloads, signatures or keys are stored.

A committed `outcome_unknown` reservation is written before the handler. Reusing
either the sender/message pair or the sender/operation pair is rejected, including
after restart or switching SDKs. A valid normal handler response changes that exact
reservation to `handler_returned`. Exceptions, error responses, invalid response
models and completion-write errors retain `outcome_unknown`; completion failure
must not be reported as success. A local normal return does not prove that an
external effect occurred. Neither state permits replay. HTTP delivery can fail after a valid signed and serializable normal return has
been recorded. Response preparation failures retain outcome_unknown.

## Python

```python
from ordavyn import Identifier, Ordavyn, SQLiteJournal, Ed25519Keypair

recipient = Identifier('participant', 'service')
signer = Ed25519Keypair.generate()  # Load the configured signer after a real restart.
# Provision once. Fails if the file exists; never replaces a previous journal.
journal = SQLiteJournal.create('/trusted/local/service.sqlite', recipient, 10000)
server = Ordavyn(participant=recipient, replay_capacity=10000, journal=journal, signer=signer)
# Configure trust and expose handlers exactly as for the memory mode.
# Once handlers have finished:
server.stop()
journal.close()

# After restart: open never creates a missing file.
journal = SQLiteJournal.open('/trusted/local/service.sqlite', recipient, 10000)
for entry in journal.inspect():
    if entry['state'] == 'outcome_unknown':
        print('Application reconciliation required:', entry['operation'])
server = Ordavyn(participant=recipient, replay_capacity=10000, journal=journal, signer=signer)
# Reconfigure local grants/handlers. Do not resubmit uncertain operations.
```

`MemoryJournal(recipient, capacity)` selects the temporary adapter explicitly.
Local inspection is not an HTTP status API. Keep journal identifiers private.
`stop()` does not close a shared journal and does not cancel an active handler.
`close()` rejects an active reservation; wait for application work to finish first.

## Rust

```rust
use ordavyn_core::{Identifier, Journal, Ed25519Keypair};
use ordavyn_core::transport::OrdavynServer;
use std::sync::Arc;

# fn example() -> ordavyn_core::Result<()> {
let recipient = Identifier::new("participant", "service");
let journal = Arc::new(Journal::create("/trusted/local/service.sqlite", recipient.clone(), 10000)?);
let server = OrdavynServer::with_journal(recipient.clone(), 10000, journal.clone())?
    .with_signer(Ed25519Keypair::generate());
// Configure trust and handlers, then wait for all dispatch calls to finish.
drop(server);
journal.close()?;
let reopened = Arc::new(Journal::open("/trusted/local/service.sqlite", recipient, 10000)?);
for entry in reopened.inspect()? {
    // Reconcile Outcome::OutcomeUnknown in the application; never auto-retry it.
    println!("{:?}", entry.state);
}
# Ok(()) }
```

`Journal::memory` selects temporary storage. A `Reservation` keeps the journal open
until it is dropped, including when a handler panics. Dropping a reservation only
ends local handler ownership; it never removes the stored replay barrier.

## Storage and recovery boundaries

Only ordinary files on a trusted local filesystem are supported; symlink targets,
SQLite URI options, in-memory SQLite, network filesystems and cloud storage are
not supported. The caller must provide a trusted directory and local filesystem;
the SDK cannot establish the filesystem's reliability. Choose a private file path
outside source/package trees (the examples require the directory to exist).
Do not replace, delete or restore an older file. Administrator rollback/deletion
and storage-device failure are outside the guarantee. A failed creation can leave
an unusable file: the SDK will not delete it or automatically recreate it.

Creation is exclusive. Opening requires the same recipient and positive capacity,
known schema version 1, valid canonical identifier blobs, known states and valid
uniqueness constraints. Corruption, mismatched configuration, lock timeout, full
capacity and storage errors fail closed. There is no fallback to memory, eviction,
reset, automatic retry, backup or automatic application recovery.

Each file stores `metadata(version, recipient, capacity)` and
`operations(sender, message, operation, state)`. Identifier BLOBs encode the CBOR
array `[namespace, value, version]`, including `null` and the full unsigned 64-bit
version range. Separate unique indexes protect `(sender,message)` and
`(sender,operation)`. `BEGIN IMMEDIATE` serializes replay/capacity checks and insert;
the transaction commits before invoking application code. The configured and
checked settings are DELETE journaling, `synchronous=EXTRA` and a 3000 ms busy
wait. EXTRA includes directory synchronization when removing the rollback journal;
see [SQLite's synchronization documentation](https://www.sqlite.org/pragma.html#pragma_synchronous).
Python uses the standard `sqlite3` module; Rust uses `rusqlite` 0.38.0 with bundled
SQLite (`libsqlite3-sys` 0.36.0), recorded in Cargo.lock.

The application must reconcile uncertain outcomes against its own source of truth.
This is a persistent admission barrier, not exactly-once execution of external
systems. Local [key revocation and bounded stopping](LOCAL-LIFECYCLE.md) preserve these
barriers. Keys and permissions are never stored in this journal; after a process
restart the application loads current grants separately. Stop/resume of the same
server retains its grants and replay records. Neither closes the journal; wait for
a completed stop before closing it. No production approval or supported package
release is implied by these features.

See the [authenticated v3 exchange guide](LOCAL-WIRE-V3.md) for explicit TLS 1.3 configuration,
protocol pins, HTTP test mode without confidentiality and the threat model.
