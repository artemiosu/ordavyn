# Wire v2 vector provenance

`wire-v2.json` was generated using Python `Message.sign` by the local generator
`/tmp/create_v2_vectors.py`. It contains fixed test keys, complete envelopes,
expected signing bytes and expected signatures. Rust independently reconstructs
and signs each message, compares those literal bytes/signatures, and verifies the
Python signature; Python also verifies the stored vectors. Tests never regenerate
expected values at runtime.

These vectors demonstrate agreement between the two implementations for the listed
cases. The original generator shares the Python implementation, so its output is
not an independent specification oracle. Cross-language agreement and fixed
regressions are not independent certification, a security audit, or proof of
correctness for all possible messages. The keys are public test material only.

## Wire v3

`wire-v3.json` retains numeric request cases and adds signed success/error responses
and a full-request binding digest. It was generated with the v3 Python codec; both
SDKs verify and independently reproduce the literal bytes/signatures. Malformed
v2 JSON examples were moved to v3 metadata to preserve their rejection coverage.
The historical v2 fixture is unchanged. All keys here are public test material.
