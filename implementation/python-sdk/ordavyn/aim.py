"""AIM primitive types — Abstract Information Model (AIM v1.0.1).

Implements the core types: Identifier, Reference, Instant, Duration, WallclockInstant.
Also implements the four-valued distinction: absent / explicit-empty / unknown / invalid.
"""

from dataclasses import dataclass, field
from typing import Optional, Union
import json


# ============================================================================
# Four-valued distinction (AIM §4)
# ============================================================================

class ValueState:
    """Four-valued field state (AIM §4)."""
    ABSENT = "absent"
    EXPLICIT_EMPTY = "explicit-empty"
    UNKNOWN = "unknown"
    INVALID = "invalid"

    ALL = {ABSENT, EXPLICIT_EMPTY, UNKNOWN, INVALID}

    @staticmethod
    def is_valid(state: str) -> bool:
        return state in ValueState.ALL


# ============================================================================
# Identifier (AIM §9)
# ============================================================================

@dataclass(frozen=True)
class Identifier:
    """Ordavyn Identifier — typed (namespace, value, version?) tuple (AIM §9.1).

    Immutable. Equality is component-wise (AIM §9.2).
    Namespace alphabet: URN RFC 8141 subset (a-z, 0-9, -, ., :).
    """
    namespace: str
    value: str
    version: Optional[int] = None

    def __post_init__(self):
        if not self.namespace:
            raise ValueError("namespace must be non-empty")
        if not self.value:
            raise ValueError("value must be non-empty")
        if not self._validate_namespace():
            raise ValueError(f"namespace '{self.namespace}' contains invalid characters")

    def _validate_namespace(self) -> bool:
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.:")
        return all(c in allowed for c in self.namespace)

    def is_valid(self) -> bool:
        return self._validate_namespace() and bool(self.value)

    def to_dict(self) -> dict:
        d = {"namespace": self.namespace, "value": self.value, "version": self.version}
        if self.version is not None:
            d["version"] = self.version
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Identifier":
        if not isinstance(d, dict) or set(d) != {"namespace", "value", "version"} or d.keys() - {"namespace", "value", "version"}:
            raise ValueError("invalid identifier fields")
        if (type(d['namespace']) is not str or type(d['value']) is not str
                or not d['value'] or len(d['value'].encode("utf-8")) > 256 or len(d['namespace'].encode("utf-8")) > 256
                or (d.get('version') is not None and (type(d['version']) is not int or not 0 <= d['version'] < 2**64))):
            raise ValueError("invalid identifier metadata")
        return cls(
            namespace=d["namespace"],
            value=d["value"],
            version=d.get("version"),
        )

    def __str__(self) -> str:
        if self.version is not None:
            return f"{self.namespace}:{self.value}:{self.version}"
        return f"{self.namespace}:{self.value}"

    def __lt__(self, other: "Identifier") -> bool:
        """Lexicographic order: (namespace, value, version). Absent version < any present."""
        self_key = (self.namespace, self.value, self.version if self.version is not None else -1)
        other_key = (other.namespace, other.value, other.version if other.version is not None else -1)
        return self_key < other_key


# ============================================================================
# Reference (AIM §10)
# ============================================================================

@dataclass(frozen=True)
class Reference:
    """Ordavyn Reference — typed pointer to another AIM object (AIM §10.1).

    Carries: declared target type, target Identifier, optional closure version.
    Target MUST be a non-Reference AIM object.
    """
    target_type: str
    target_id: Identifier
    closure_version: Optional[int] = None

    def to_dict(self) -> dict:
        d = {"target_type": self.target_type, "target_id": self.target_id.to_dict(), "closure_version": self.closure_version}
        if self.closure_version is not None:
            d["closure_version"] = self.closure_version
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Reference":
        if not isinstance(d, dict) or set(d) != {"target_type", "target_id", "closure_version"} or d.keys() - {"target_type", "target_id", "closure_version"}:
            raise ValueError("invalid reference fields")
        if (type(d['target_type']) is not str or not d['target_type'] or len(d['target_type'].encode("utf-8")) > 256
                or (d.get('closure_version') is not None and
                    (type(d['closure_version']) is not int or not 0 <= d['closure_version'] < 2**64))):
            raise ValueError("invalid reference metadata")
        return cls(
            target_type=d["target_type"],
            target_id=Identifier.from_dict(d["target_id"]),
            closure_version=d.get("closure_version"),
        )

    def __str__(self) -> str:
        if self.closure_version is not None:
            return f"Reference<{self.target_type}>({self.target_id}@{self.closure_version})"
        return f"Reference<{self.target_type}>({self.target_id})"


# ============================================================================
# Instant (AIM §8.1) — per-context monotonic logical time
# ============================================================================

@dataclass(frozen=True)
class Instant:
    """Monotonic logical time, per-context (AIM §8.1).

    Cross-context comparison is invalid without explicit projection.
    """
    nanos: int

    @classmethod
    def from_millis(cls, millis: int) -> "Instant":
        return cls(nanos=millis * 1_000_000)

    @classmethod
    def from_secs(cls, secs: int) -> "Instant":
        return cls(nanos=secs * 1_000_000_000)

    def duration_since(self, other: "Instant") -> Optional["Duration"]:
        """Subtract two Instants → Duration. Returns None if negative."""
        if self.nanos < other.nanos:
            return None
        return Duration(nanos=self.nanos - other.nanos)

    def to_dict(self) -> dict:
        return {"nanos": self.nanos}

    @classmethod
    def from_dict(cls, d: dict) -> "Instant":
        if not isinstance(d, dict) or set(d) != {"nanos"}:
            raise ValueError("invalid instant fields")
        if type(d['nanos']) is not int or not 0 <= d['nanos'] < 2**64:
            raise ValueError("invalid instant metadata")
        return cls(nanos=d["nanos"])

    def __str__(self) -> str:
        return f"Instant({self.nanos}ns)"


# ============================================================================
# Duration (AIM §8.2) — non-negative
# ============================================================================

@dataclass(frozen=True)
class Duration:
    """Non-negative duration in nanoseconds (AIM §8.2)."""
    nanos: int

    def __post_init__(self):
        if self.nanos < 0:
            raise ValueError("Duration must be non-negative")

    @classmethod
    def from_millis(cls, millis: int) -> "Duration":
        return cls(nanos=millis * 1_000_000)

    @classmethod
    def from_secs(cls, secs: int) -> "Duration":
        return cls(nanos=secs * 1_000_000_000)

    def add(self, other: "Duration") -> "Duration":
        return Duration(nanos=self.nanos + other.nanos)

    def sub(self, other: "Duration") -> Optional["Duration"]:
        if self.nanos < other.nanos:
            return None
        return Duration(nanos=self.nanos - other.nanos)

    def is_zero(self) -> bool:
        return self.nanos == 0

    def to_dict(self) -> dict:
        return {"nanos": self.nanos}

    @classmethod
    def from_dict(cls, d: dict) -> "Duration":
        return cls(nanos=d["nanos"])

    def __str__(self) -> str:
        return f"Duration({self.nanos}ns)"


# ============================================================================
# WallclockInstant (AIM §8.3)
# ============================================================================

@dataclass
class WallclockInstant:
    """Civil time with explicit uncertainty (AIM §8.3).

    NOT comparable to Instant without explicit projection.
    Zero uncertainty does NOT collapse the domain distinction.
    """
    central: int
    uncertainty: Union[Duration, str]  # Duration or "unknown"

    @classmethod
    def with_known_uncertainty(cls, central: int, uncertainty: Duration) -> "WallclockInstant":
        return cls(central=central, uncertainty=uncertainty)

    @classmethod
    def with_unknown_uncertainty(cls, central: int) -> "WallclockInstant":
        return cls(central=central, uncertainty="unknown")

    def has_zero_uncertainty(self) -> bool:
        if isinstance(self.uncertainty, Duration):
            return self.uncertainty.is_zero()
        return False

    def to_dict(self) -> dict:
        if isinstance(self.uncertainty, Duration):
            return {"central": self.central, "uncertainty": self.uncertainty.to_dict()}
        return {"central": self.central, "uncertainty": "unknown"}

    def __str__(self) -> str:
        if isinstance(self.uncertainty, Duration):
            return f"WallclockInstant({self.central}±{self.uncertainty.nanos}ns)"
        return f"WallclockInstant({self.central}±unknown)"
