# Local admission and lifecycle

Both SDKs provide local `trust`, `revoke`, `rotate_key`, `request_stop`, `stop`
and `resume` operations. These are application APIs, not HTTP management routes.
They apply equally to direct calls, HTTP calls and Rust server clones.

A successful journal reservation is the admission point. Signature, permission,
admission gate and reservation are checked under the same policy lock. Revocation
or stopping before this point prevents the request without a journal entry or
handler effect. A request admitted first may finish, even if its handler function
has not started yet. Handlers run outside the policy lock. No method forcibly
cancels a handler or undoes an external effect.

## Permissions

`trust(public_key, participant, actions)` requires a nonempty set of explicit
valid action names. For an existing exact key and participant it replaces the
permissions, so applications can narrow them. A different participant binding or
key-ID collision is rejected without changing the old grant.

`revoke(public_key)` removes only the exact key and reports whether it existed.
Trusting it again is an explicit new grant. `rotate_key(old_key, new_key)` moves
the old participant and actions atomically. A missing old key, identical keys,
an already registered new key or a key-ID conflict fails without partial changes.
Rotation preserves all message and operation replay barriers for that participant.

## Python example

This example uses direct calls; the same policy governs `server.start()` and HTTP.

```python
from ordavyn import Ordavyn, Identifier, Ed25519Keypair, MessageBuilder, MessageType

caller = Identifier('participant', 'caller')
service = Identifier('participant', 'service')
old = Ed25519Keypair.generate()
new = Ed25519Keypair.generate()
server = Ordavyn(port=0, participant=service)
server.trust(old.public_key_bytes(), caller, ['status'])
server.expose('/status')(lambda: {'ready': True})
request = MessageBuilder(caller, service).payload({'action': 'status'}).build()
request.sign(old)
assert server._handle_request(request).msg_type == MessageType.RESPONSE
server.rotate_key(old.public_key_bytes(), new.public_key_bytes())
request.sign(new)
assert server._handle_request(request).msg_type == MessageType.ERROR  # still a replay
assert server.revoke(new.public_key_bytes())
assert server.stop(timeout=4.0)
server.resume()
# Revocation survives resume; the application must explicitly grant access again.
assert server._handle_request(request).msg_type == MessageType.ERROR
```

`request_stop()` closes admission and asks the listener to stop without waiting
for handlers. Synchronous `stop(timeout=4.0)` does that and returns whether all
handlers and network work finished. Timeout must be finite, nonnegative and no
larger than Python's `threading.TIMEOUT_MAX`; invalid values raise `ValueError`
before changing state. The waiting timeout starts after the admission gate has
closed. Closing that gate first waits for an in-progress signature/admission check
or bounded SQLite reservation (up to the configured 3000 ms busy wait), but never
for a handler. Thus the whole call can take longer than its waiting timeout.
`stop(0)` is an immediate completion check after closing
admission. A false return leaves the gate closed and the journal open.

## Rust example

Within an async application, with a configured `OrdavynServer`, use:

```rust
use std::time::Duration;
// `server`, `old_key` and `new_key` are application-owned configured values.
server.rotate_key(&old_key.public_key(), new_key.public_key())?;
assert!(server.revoke(&new_key.public_key())?);
server.request_stop();
if server.stop(Duration::from_secs(4)).await {
    server.resume()?;
}
```

Rust `stop(Duration)` is async and returns a completion boolean. Its waiting
timeout likewise begins only after closing the gate, including any bounded
admission/storage wait needed to acquire that gate. Use four seconds
for the standard wait; `Duration::ZERO` checks without waiting. The type excludes
negative and nonfinite intervals; an interval outside the monotonic clock's range
is rejected by a panic before admission changes. Direct `dispatch` remains
synchronous. HTTP uses one blocking worker per sequential connection, so a handler
does not block a current-thread Tokio runtime. Cancelling a serve future does not
cancel that worker: it remains counted until it finishes, including queued work.
A new listener cannot start while an old worker remains. No unbounded worker
queue is created by incoming HTTP connections on a server object.

## Stop and resume rules

The initial direct-call gate is open. `resume()` explicitly reopens it only when
all previous handler and network work has finished. Python `start()` and Rust
`serve`, `serve_one`, `serve_listener_one` can also reopen a fully stopped object.
Concurrent listener starts fail; failed binds do not leave a running listener.
All Rust clones share the gate and work accounting.

A handler may call `request_stop()`. Waiting for itself can only time out, so
prefer the nonwaiting method inside handlers. Repeat `stop` later to observe
completion. A timed-out or disconnected caller has no cancellation guarantee. The HTTP
deadline bounds I/O. In Rust, awaiting an admitted handler retains the connection
until that handler finishes, or stop/cancellation ends the network task; its
blocking worker remains tracked independently until actual exit. In Python, a
connection already executing a handler remains owned until that handler exits.
Stopping is idempotent; a completed stop means no active handler, listener or
unfinished network worker remains. The application should coordinate management
calls if another thread could explicitly resume immediately afterwards.

Neither stop nor resume clears grants, revocations or replay records, and neither
closes the journal. The application may close the journal after a completed stop;
a closed journal must not be reused. In a new process, load current grants from
application configuration. Journals never store keys or permissions. SQLite
replay barriers survive reopen and key changes; memory barriers last only as long
as that journal object. See [LOCAL-JOURNAL.md](LOCAL-JOURNAL.md).

This is local admission control, not distributed revocation, TLS, production
approval or a public release. Wire v2 and the SQLite schema remain unchanged.
