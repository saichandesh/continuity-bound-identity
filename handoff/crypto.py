"""Keys and signing.

Three key models, differing ONLY in which properties they enforce:

  SoftwareKey     - exportable. Lives in agent state, so copying the agent copies the key.
  HardwareKey     - non-exportable, bound to one host (TPM-like). Any process on that
                    host can ask it to sign. A copy on another host cannot sign.
  RuntimeBoundKey - HardwareKey + a trusted runtime that attests WHICH process instance
                    requested the signature. Each process launch gets a fresh,
                    unforgeable instance id.

Important: none of these attest who DECIDED the action. A process that holds the key
can sign on behalf of anyone who sends it a request (see the funnel attack).
"""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha(data) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = canonical(data)
    return hashlib.sha256(data).hexdigest()


def verify(pub, sig: bytes, msg: bytes) -> bool:
    try:
        pub.verify(sig, msg)
        return True
    except InvalidSignature:
        return False


class KeyUnavailable(Exception):
    """Raised when a process cannot use a key (e.g. hardware key on another host)."""


class SoftwareKey:
    kind = "software"

    def __init__(self, sk=None):
        self._sk = sk or Ed25519PrivateKey.generate()

    def public(self):
        return self._sk.public_key()

    def sign(self, process, msg: bytes):
        return self._sk.sign(msg), None

    def copy(self):
        # Copying agent state copies the secret itself.
        return SoftwareKey(self._sk)


class HardwareKey:
    kind = "hardware"

    def __init__(self, host: str):
        self._sk = Ed25519PrivateKey.generate()
        self.host = host

    def public(self):
        return self._sk.public_key()

    def sign(self, process, msg: bytes):
        if process.host != self.host:
            raise KeyUnavailable(f"key bound to {self.host}, caller on {process.host}")
        return self._sk.sign(msg), None

    def copy(self):
        # Copying agent state only copies a handle; the secret stays in the host's chip.
        return self


class TrustedRuntime:
    """Stands in for an attestation service (TEE / measured runtime)."""

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()

    def public(self):
        return self._sk.public_key()

    def attest(self, process, msg: bytes):
        statement = {"instance_id": process.instance_id, "host": process.host, "msg": sha(msg)}
        return statement, self._sk.sign(canonical(statement))


class RuntimeBoundKey(HardwareKey):
    kind = "runtime"

    def __init__(self, host: str, runtime: TrustedRuntime):
        super().__init__(host)
        self.runtime = runtime

    def sign(self, process, msg: bytes):
        sig, _ = super().sign(process, msg)
        return sig, self.runtime.attest(process, msg)
