# Ordavyn release status

Local migration candidate only. Publication remains blocked pending checks of the exact release contents
and a separately approved public file set. No push or publication was
performed; the local pre-push hook remains a blocking control.

Implemented locally: protected request dispatch in Python and Rust; Ed25519 signature
and metadata verification; explicit participant/recipient/action bindings; atomic,
bounded message and operation replay reservation; separate unsigned responses; exact
routes; bounded loopback HTTP/1.1; Ordavyn package and incompatible wire names; repaired
wheel/sdist contents; simulations using the SDK's protected server.

Journal storage now has two explicit modes: temporary memory (lost on restart)
and persistent local SQLite (opt-in, shared by both SDKs). Neither evicts records.
Handler failure does not undo an effect and does not release its reservation.
See [LOCAL-JOURNAL.md](LOCAL-JOURNAL.md) for recovery and storage assumptions. Handlers themselves are application code and have no execution timeout.
Python and Rust now implement a shared experimental local wire v2 envelope and
domain-separated deterministic CBOR signatures; see [LOCAL-WIRE-V2.md](LOCAL-WIRE-V2.md).
Version 1 is explicitly incompatible and is rejected. Responses are
unsigned. Delegation, negotiation, PQ and TLS are not implemented. No production,
real transactions or public network exposure is authorized.

Verification evidence is retained in the excluded local implementation report.
Passing tests is not a security audit, legal clearance or protocol certification.
The original Apache text and conflicting Cargo declaration are preserved externally;
see [PROVENANCE.md](PROVENANCE.md). On 2026-09-27 the owner selected Apache-2.0.
Standard license files and package metadata now reflect that selection; no
rights-holder identity was invented and no third-party rights were established.
The owner subsequently confirmed that the project code was created solely by
them with AI assistance. The code-origin question is answered by that declaration;
dependency licenses and release-content checks remain separate.

CBOR transport decoding, CBOR decoder resource-limit enforcement and streaming
transport are unsupported. Rust CBOR depth/collection constants are proposed
values only; they are not enforced decoder limits and their values do not prove
resource protection. The implemented HTTP JSON byte limits are separate.
HTTP/2 streams and concurrent-stream limits are also unsupported.

Further release checks remain open. Migration does not establish name or trademark
rights, domain availability, or public package-name availability. Provenance,
dependency and secret checks for the exact proposed public snapshot must still be
completed. Public specifications and governance documents require separate curation
and review. Earlier AD-15/AD-16 release conditions are not declared satisfied by this
work. The license selection and explicit owner publication approval do not replace
these checks; no legal determination is made here.

Deferred limitations B4/B6: grants are static local configuration, not a complete
runtime key-revocation mechanism. Stopping the Python server closes its listener
but does not cancel an already running handler; that handler may still finish its
effect. Do not restart while a handler is active; start rejects an existing live
server thread. These limits are not resolved by the current request protections.

Final local verification (2026-09-27): 66 Rust tests and release build passed;
97 Python behavioral tests passed against each independently installed wheel and
sdist. Both demos and the SDK README example passed in both environments. Three
BMAD review lenses were completed and accepted fixes were verified. The two
deferred lifecycle limitations above remain open. These are local test results,
not release approval or independent protocol certification.

License-selection follow-up (2026-09-27): standard Apache-2.0 text was checked
byte-for-byte in all four local LICENSE files, the rebuilt wheel and sdist.
Wheel metadata declares Apache-2.0 and retains its private classifier; Cargo
metadata declares Apache-2.0 and retains `publish = false`. The Rust package
file list includes LICENSE. No runtime code changed; the behavioral test counts
above refer to the preceding implementation verification, not a new test run.
The pre-push hook is byte-for-byte unchanged.

Wire v2 implementation (2026-09-28): strict JSON transport and direct API validation
now agree on mandatory envelope/AIM fields, scalar Unicode, 256-byte AIM strings,
integer boundaries, finite binary64 values and tree depth <=32. The old tagged AIM
CBOR helpers are not used for v2 signing. Python pins cbor2 5.9.0's Python canonical
encoder to avoid the C accelerator's non-shortest encoding at 65504.0. These changes
do not close architecture release conditions or authorize publication. Fresh test
evidence is recorded separately from the historical September 27 results above.

Wire v2 size correction (2026-09-28): all model APIs use the same 64 KiB
deterministic CBOR budget, including the signature. HTTP applies its separate
64 KiB cap to actual input/output bytes, without receiver-specific JSON
reserialization. Live checks include independent signed-invalid-shape requests,
recovery with the rejected IDs, separate message/operation replay, small journal
exhaustion, numeric/optional vectors and an exact 65536-byte input in both directions.

Итог проверки wire v2 (2026-09-28): 74 теста Rust и release build прошли;
по 146 тестов Python прошли после независимой установки wheel и sdist вне
исходного дерева. В каждом окружении проверены оба направления живого обмена
(12 эффектов и 31 отказ на направление), оба демо и пример README. Два прохода
трёх направлений BMAD ревью завершены; принятые исправления проверены.

Отложенное ограничение R2-B4: Python возвращает HTTP 403 при ошибке обработчика,
а Rust-клиент отклоняет такой статус до разбора тела ошибки. Успешный обмен
совместим; одинаковая обработка всех ошибок между SDK пока не обеспечена.
Результаты относятся к локальному прототипу и не разрешают публикацию.


Durable replay implementation (2026-09-28): both SDKs can create or open a local
SQLite journal bound to recipient and capacity. Admission commits before execution;
normal valid return is recorded separately. Unknown outcomes require application
reconciliation and cannot be automatically retried. Storage failure denies action
or denies successful completion reporting; no memory fallback, reset or eviction
is provided. SQLite storage is local and trusted; device failure and administrator
file rollback/deletion remain outside the guarantee. This does not establish
exactly-once external effects or change wire v2, key grants, TLS or publication status.
Fresh verification evidence is recorded separately from the historical results.

Итог постоянного журнала (2026-09-28): 82 теста Rust и release build прошли.
Свежие wheel/sdist независимо установлены вне исходной папки: в каждой установке
прошли 184 теста SDK, 35 проверок восстановления/гонок, живой обмен двух SDK,
оба демо и пример README. Примеры нового руководства также выполнены.
Три направления BMAD-ревью завершены; все принятые замечания исправлены и
проверены полным прогоном. Новых отложенных замечаний этого этапа нет.
Ранее перечисленные ограничения и условия публикации остаются в силе.
