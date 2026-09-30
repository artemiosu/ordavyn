# Draft 0.1 conformance evidence

This is traceability, not certification. Each stable ID names a requirement group;
the selectors below provide positive and negative executable evidence for that
group rather than claiming one test per sentence.

`implemented` means the repository contains the named executable positive and
negative evidence. It does not assert that every repository SDK independently
conforms. An `unsupported` requirement group uses an explicit `—` in both evidence
columns and claims no executable support; every normative ID still appears once.

| Requirement | Status | Positive evidence | Negative evidence |
|---|---|---|---|
| [ORD-ENV-001](ORDAVYN-WIRE-V3.md#ord-env-001--strict-envelope-and-json-values) | implemented | `implementation/python-sdk/tests/test_interop.py::test_frozen_vectors` | `implementation/ordavyn-core/tests/interop.rs::strict_json_rejections` |
| [ORD-ENV-002](ORDAVYN-WIRE-V3.md#ord-env-002--envelope-semantics) | implemented | `implementation/ordavyn-core/tests/interop.rs::frozen_cross_language_vectors` | `implementation/python-sdk/tests/test_interop.py::test_invalid_envelope` |
| [ORD-CAN-001](ORDAVYN-WIRE-V3.md#ord-can-001--deterministic-signing-input) | implemented | `implementation/python-sdk/tests/test_interop.py::test_fixed_request_digest_and_signed_response_vectors` | `implementation/python-sdk/tests/test_security.py::test_object_array_signature_distinct` |
| [ORD-SIG-001](ORDAVYN-WIRE-V3.md#ord-sig-001--ed25519-authentication) | implemented | `implementation/ordavyn-core/tests/interop.rs::fixed_request_binding_and_signed_responses` | `implementation/ordavyn-core/tests/security.rs::negative_matrix` |
| [ORD-BIND-001](ORDAVYN-WIRE-V3.md#ord-bind-001--complete-request-binding) | implemented | `implementation/ordavyn-core/tests/exchange.rs::complete_request_binding_includes_payload_and_signature` | `implementation/ordavyn-core/tests/security.rs::client_checks_each_response_correlation_field` |
| [ORD-ADM-001](ORDAVYN-WIRE-V3.md#ord-adm-001--admission-order) | implemented | `implementation/python-sdk/tests/test_security.py::test_authorized_direct_and_request_unchanged` | `implementation/python-sdk/tests/test_security.py::test_rejected_before_effect` |
| [ORD-REP-001](ORDAVYN-WIRE-V3.md#ord-rep-001--replay-barrier) | implemented | `implementation/ordavyn-core/tests/journal.rs::dispatch_failure_stays_unknown_and_success_is_recorded` | `implementation/ordavyn-core/tests/security.rs::message_id_replay_with_fresh_operation_and_spare_capacity` |
| [ORD-LIFE-001](ORDAVYN-WIRE-V3.md#ord-life-001--local-lifecycle) | implemented | `implementation/ordavyn-core/tests/lifecycle.rs::management_precedes_admission_without_reservation` | `implementation/python-sdk/tests/test_lifecycle.py::test_handler_can_request_stop_and_bounded_wait` |
| [ORD-RESP-001](ORDAVYN-WIRE-V3.md#ord-resp-001--correlated-results) | implemented | `implementation/tests/test_authenticated_exchange.py::test_tls_all_pairs_success_and_signed_admission_error` | `implementation/tests/test_authenticated_exchange.py::test_clients_reject_untrusted_response` |
| [ORD-ERR-001](ORDAVYN-WIRE-V3.md#ord-err-001--errors-and-unknown-outcomes) | implemented | `implementation/python-sdk/tests/test_review_regressions.py::test_handler_serialization_errors_keep_reservation` | `implementation/tests/test_authenticated_exchange.py::test_tls_signed_errors_after_effect_retain_barrier` |
| [ORD-HTTP-001](ORDAVYN-WIRE-V3.md#ord-http-001--local-http11) | implemented | `implementation/python-sdk/tests/test_security.py::test_http_matrix_and_fragmented_unicode` | `implementation/ordavyn-core/tests/security.rs::client_rejects_response_version_and_limits` |
| [ORD-TLS-001](ORDAVYN-WIRE-V3.md#ord-tls-001--optional-tls) | implemented | `implementation/tests/test_authenticated_exchange.py::test_ip_san_is_verified` | `implementation/tests/test_authenticated_exchange.py::test_tls12_rejected_before_reservation` |
| [ORD-LIM-001](ORDAVYN-WIRE-V3.md#ord-lim-001--budgets) | implemented | `implementation/ordavyn-core/tests/interop.rs::model_budget_independent_of_json_and_exact_boundary` | `implementation/python-sdk/tests/test_security.py::test_http_header_body_limits_and_timeout` |
| [ORD-VER-001](ORDAVYN-WIRE-V3.md#ord-ver-001--versioning-and-extensions) | implemented | `implementation/ordavyn-core/tests/interop.rs::frozen_cross_language_vectors` | `implementation/python-sdk/tests/test_interop.py::test_invalid_envelope` |
| [ORD-PRIV-001](ORDAVYN-WIRE-V3.md#ord-priv-001--privacy-boundary) | implemented | `tools/tests/test_export_release.py::ExportCheckTests.test_accepts_complete_source_only_classification` | `tools/tests/test_export_release.py::ExportCheckTests.test_rejects_private_path_even_if_classified` |
| [ORD-CONF-001](ORDAVYN-WIRE-V3.md#ord-conf-001--evidence-boundary) | implemented | `tools/tests/test_public_spec.py::PublicSpecTests.test_checked_in_spec_is_complete` | `tools/tests/test_public_spec.py::PublicSpecTests.test_rejects_missing_evidence_class` |

## Unsupported inventory — Draft 0.1

The validator requires this exact versioned inventory:

- automatic retries
- CBOR decoder resource-limit enforcement
- CBOR transport decoding
- delegation
- discovery
- exactly-once external effects
- event dispatch and delivery semantics
- HTTP/2 streams and concurrent-stream limits
- mTLS
- negotiation
- post-quantum signatures
- production or remote-deployment profile
- streaming transport
- vendor extension registry
