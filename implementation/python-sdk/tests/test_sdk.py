"""Tests for Ordavyn Python SDK."""

from ordavyn import (
    Identifier, Reference, Instant, Duration, WallclockInstant, ValueState,
    Ed25519Keypair, Message, MessageBuilder, MessageType,
)


# ============================================================================
# AIM type tests
# ============================================================================

def test_identifier_new():
    id = Identifier("participant", "alice")
    assert id.namespace == "participant"
    assert id.value == "alice"
    assert id.version is None

def test_identifier_with_version():
    id = Identifier("artifact", "core", 3)
    assert id.version == 3

def test_identifier_equality():
    a = Identifier("ns", "val")
    b = Identifier("ns", "val")
    c = Identifier("ns", "other")
    assert a == b
    assert a != c

def test_identifier_version_equality():
    v1 = Identifier("ns", "val", 1)
    v2 = Identifier("ns", "val", 2)
    assert v1 != v2

def test_identifier_ordering():
    a = Identifier("a", "1")
    b = Identifier("a", "2")
    c = Identifier("b", "1")
    assert a < b
    assert b < c

def test_identifier_version_ordering():
    absent = Identifier("ns", "val")
    v0 = Identifier("ns", "val", 0)
    v1 = Identifier("ns", "val", 1)
    assert absent < v0
    assert v0 < v1

def test_identifier_invalid_namespace():
    try:
        Identifier("", "val")
        assert False, "should raise"
    except ValueError:
        pass

    try:
        Identifier("UPPER", "val")
        assert False, "should raise"
    except ValueError:
        pass

def test_identifier_roundtrip():
    id = Identifier("ns", "val", 42)
    d = id.to_dict()
    id2 = Identifier.from_dict(d)
    assert id == id2

def test_reference_new():
    id = Identifier("artifact", "core")
    r = Reference("Artifact", id)
    assert r.target_type == "Artifact"
    assert r.target_id == id
    assert r.closure_version is None

def test_reference_roundtrip():
    r = Reference("Artifact", Identifier("ns", "val"), 42)
    d = r.to_dict()
    r2 = Reference.from_dict(d)
    assert r == r2

def test_instant_ordering():
    a = Instant.from_secs(100)
    b = Instant.from_secs(200)
    assert a.nanos < b.nanos

def test_instant_duration_since():
    a = Instant.from_secs(200)
    b = Instant.from_secs(100)
    d = a.duration_since(b)
    assert d is not None
    assert d.nanos == 100 * 1_000_000_000

def test_instant_duration_since_negative():
    a = Instant.from_secs(100)
    b = Instant.from_secs(200)
    assert a.duration_since(b) is None

def test_duration_add():
    a = Duration.from_secs(100)
    b = Duration.from_secs(200)
    c = a.add(b)
    assert c.nanos == 300 * 1_000_000_000

def test_duration_sub_negative():
    a = Duration.from_secs(100)
    b = Duration.from_secs(200)
    assert a.sub(b) is None

def test_duration_zero_is_valid():
    zero = Duration(nanos=0)
    assert zero.is_zero()

def test_wallclock_zero_uncertainty():
    w = WallclockInstant.with_known_uncertainty(1000, Duration(nanos=0))
    assert w.has_zero_uncertainty()

def test_wallclock_unknown_uncertainty():
    w = WallclockInstant.with_unknown_uncertainty(1000)
    assert not w.has_zero_uncertainty()

def test_value_state_distinct():
    states = [ValueState.ABSENT, ValueState.EXPLICIT_EMPTY, ValueState.UNKNOWN, ValueState.INVALID]
    for i, a in enumerate(states):
        for j, b in enumerate(states):
            if i == j:
                assert a == b
            else:
                assert a != b


# ============================================================================
# Crypto tests
# ============================================================================

def test_keypair_generation():
    kp1 = Ed25519Keypair.generate()
    kp2 = Ed25519Keypair.generate()
    assert kp1.public_key_bytes() != kp2.public_key_bytes()

def test_sign_and_verify():
    kp = Ed25519Keypair.generate()
    message = b"Hello, Ordavyn!"
    signature = kp.sign(message)
    assert Ed25519Keypair.verify(kp.public_key_bytes(), message, signature)

def test_verify_wrong_message():
    kp = Ed25519Keypair.generate()
    sig = kp.sign(b"correct message")
    assert not Ed25519Keypair.verify(kp.public_key_bytes(), b"wrong message", sig)

def test_verify_wrong_key():
    kp1 = Ed25519Keypair.generate()
    kp2 = Ed25519Keypair.generate()
    sig = kp1.sign(b"test")
    assert not Ed25519Keypair.verify(kp2.public_key_bytes(), b"test", sig)

def test_signature_is_64_bytes():
    kp = Ed25519Keypair.generate()
    sig = kp.sign(b"test")
    assert len(sig) == 64

def test_key_id_is_16_hex():
    kp = Ed25519Keypair.generate()
    kid = kp.key_id()
    assert len(kid) == 16
    assert all(c in "0123456789abcdef" for c in kid)

def test_signing_deterministic():
    """Ed25519 is deterministic — same key + message = same signature."""
    kp = Ed25519Keypair.generate()
    msg = b"test message"
    sig1 = kp.sign(msg)
    sig2 = kp.sign(msg)
    assert sig1 == sig2


# ============================================================================
# Message tests
# ============================================================================

def test_message_builder():
    from_id = Identifier("participant", "alice")
    to_id = Identifier("participant", "bob")
    msg = MessageBuilder(from_id, to_id).payload({"action": "search"}).build()
    assert msg.version == 1
    assert msg.msg_type == MessageType.REQUEST
    assert msg.from_id == from_id
    assert msg.to_id == to_id
    assert not msg.is_signed()

def test_message_sign_and_verify():
    from_id = Identifier("participant", "alice")
    to_id = Identifier("participant", "bob")
    msg = (MessageBuilder(from_id, to_id)
           .id(Identifier("message", "test-001"))
           .operation_id(Identifier("logical-operation", "test-op-001"))
           .payload({"action": "buy", "product_id": "12345"})
           .build())

    kp = Ed25519Keypair.generate()
    msg.sign(kp)
    assert msg.is_signed()
    assert msg.verify_signature(kp.public_key_bytes())

def test_message_verify_tampered():
    from_id = Identifier("participant", "alice")
    to_id = Identifier("participant", "bob")
    msg = (MessageBuilder(from_id, to_id)
           .id(Identifier("message", "test-002"))
           .operation_id(Identifier("logical-operation", "test-op-002"))
           .payload({"amount": 100})
           .build())

    kp = Ed25519Keypair.generate()
    msg.sign(kp)

    # Tamper
    msg.payload = {"amount": 99999}
    assert not msg.verify_signature(kp.public_key_bytes())

def test_message_verify_wrong_key():
    from_id = Identifier("participant", "alice")
    to_id = Identifier("participant", "bob")
    msg = (MessageBuilder(from_id, to_id)
           .id(Identifier("message", "test-003"))
           .operation_id(Identifier("logical-operation", "test-op-003"))
           .payload({"action": "test"})
           .build())

    kp1 = Ed25519Keypair.generate()
    kp2 = Ed25519Keypair.generate()
    msg.sign(kp1)
    assert not msg.verify_signature(kp2.public_key_bytes())

def test_message_json_roundtrip():
    from_id = Identifier("participant", "alice")
    to_id = Identifier("participant", "bob")
    msg = (MessageBuilder(from_id, to_id)
           .id(Identifier("message", "rt-001"))
           .operation_id(Identifier("logical-operation", "rt-op-001"))
           .payload({"action": "search", "query": "laptop"})
           .build())

    d = msg.to_dict()
    msg2 = Message.from_dict(d)
    assert msg2.id == msg.id
    assert msg2.from_id == msg.from_id
    assert msg2.payload == msg.payload

def test_unsigned_message_verify_fails():
    from_id = Identifier("participant", "alice")
    to_id = Identifier("participant", "bob")
    msg = MessageBuilder(from_id, to_id).build()
    kp = Ed25519Keypair.generate()
    assert not msg.verify_signature(kp.public_key_bytes())


# ============================================================================
# Run all tests
# ============================================================================

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"Python SDK tests: {passed} passed, {failed} failed")
    print(f"{'='*60}")

    if failed > 0:
        exit(1)
