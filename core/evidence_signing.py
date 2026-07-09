"""
core/evidence_signing.py — Digital Evidence Signing (Phase 1C)

Cryptographically signs the SHA-256 hash produced by Phase 1A to
guarantee authenticity and non-repudiation.  Only the hash is signed —
never the file content — keeping signing fast regardless of file size
and consistent with standard forensic practice (sign the digest, not
the artifact).

Supported algorithms
--------------------
Ed25519  (default)  — 64-byte deterministic signatures, no padding
                       oracle risk, fast, constant-time verify
RSA-4096 (optional) — PSS padding, SHA-256 digest, compatible with
                       legacy forensic toolchains that expect RSA

Key storage (keys/)
-------------------
keys/
├── private/
│   └── <key_id>_<alg>.pem      # mode 0o600, never logged or returned
└── public/
    └── <key_id>_<alg>.pub.pem  # mode 0o644, safe to distribute

key_id is generated as hex(urandom(8)) at keypair creation time, giving
an 8-byte tag that is safe to log, store in the DB, and include in
exports without revealing the private key.

Verification results
--------------------
"VALID"   — signature matches the stored SHA-256 under the current key
"INVALID" — bytes on disk don't match the stored signature
"MISSING" — no signature row exists for this evidence_id yet

Thread-safety
-------------
All public functions open their own DbSession and close it before
returning; no module-level mutable state is shared across threads.
"""

import os
import stat
import json
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("EvidenceSignature")

# ── Constants ────────────────────────────────────────────────
KEYS_DIR         = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
PRIVATE_DIR      = os.path.join(KEYS_DIR, "private")
PUBLIC_DIR       = os.path.join(KEYS_DIR, "public")
ACTIVE_KEY_FILE  = os.path.join(KEYS_DIR, "active_key.json")

Algorithm = Literal["ed25519", "rsa4096"]
DEFAULT_ALG: Algorithm = "ed25519"

# Thread-lock for keypair generation/rotation (rare, but must not race)
_key_lock = threading.Lock()


# ── Internal helpers ─────────────────────────────────────────

def _ensure_dirs() -> None:
    os.makedirs(PRIVATE_DIR, exist_ok=True)
    os.makedirs(PUBLIC_DIR,  exist_ok=True)
    os.chmod(KEYS_DIR,    0o700)
    os.chmod(PRIVATE_DIR, 0o700)
    os.chmod(PUBLIC_DIR,  0o700)


def _new_key_id() -> str:
    return os.urandom(8).hex()


def _private_path(key_id: str, alg: str) -> str:
    return os.path.join(PRIVATE_DIR, f"{key_id}_{alg}.pem")


def _public_path(key_id: str, alg: str) -> str:
    return os.path.join(PUBLIC_DIR, f"{key_id}_{alg}.pub.pem")


def _fingerprint(pub_pem: bytes) -> str:
    """SHA-256 fingerprint of the DER-encoded public key, colon-separated."""
    raw = serialization.load_pem_public_key(pub_pem)
    der = raw.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))


def _write_private(path: str, pem: bytes) -> None:
    """Write private key PEM with mode 0600 — never world-readable."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _write_public(path: str, pem: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    os.chmod(path, 0o644)


def _load_active_key_meta() -> Optional[dict]:
    """Return the active key metadata dict, or None if not present."""
    if not os.path.exists(ACTIVE_KEY_FILE):
        return None
    try:
        with open(ACTIVE_KEY_FILE) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read active_key.json: {e}")
        return None


def _save_active_key_meta(meta: dict) -> None:
    tmp = ACTIVE_KEY_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=2)
    os.replace(tmp, ACTIVE_KEY_FILE)   # atomic on POSIX
    os.chmod(ACTIVE_KEY_FILE, 0o640)


# ── Key generation ───────────────────────────────────────────

def generate_keypair(alg: Algorithm = DEFAULT_ALG) -> dict:
    """
    Generate a new Ed25519 or RSA-4096 keypair, persist it to
    keys/private/ and keys/public/ with secure permissions, record it
    as the active signing key, and return the key metadata dict
    (key_id, algorithm, public_key_fingerprint, created_at).

    Private key bytes are NEVER included in the return value.
    """
    _ensure_dirs()
    with _key_lock:
        key_id    = _new_key_id()
        priv_path = _private_path(key_id, alg)
        pub_path  = _public_path(key_id, alg)

        if alg == "ed25519":
            private_key = Ed25519PrivateKey.generate()
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif alg == "rsa4096":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise ValueError(f"Unsupported algorithm '{alg}'. Use 'ed25519' or 'rsa4096'.")

        _write_private(priv_path, priv_pem)
        _write_public(pub_path, pub_pem)

        fp = _fingerprint(pub_pem)
        meta = {
            "key_id":                key_id,
            "algorithm":             alg,
            "public_key_fingerprint": fp,
            "public_key_path":       pub_path,
            "private_key_path":      priv_path,
            "created_at":            datetime.now(timezone.utc).isoformat(),
        }
        _save_active_key_meta(meta)

    logger.info(
        f"[EVIDENCE_SIGNATURE] New {alg.upper()} keypair generated. "
        f"key_id={key_id} fingerprint={fp[:23]}..."
    )
    # Return metadata only — never the PEM bytes
    return {k: v for k, v in meta.items() if k != "private_key_path"}


def load_keys() -> Optional[dict]:
    """
    Return the active key metadata dict, or None if no key has been
    generated yet.  Does NOT return or expose private key material.
    """
    meta = _load_active_key_meta()
    if meta is None:
        return None
    return {k: v for k, v in meta.items() if k != "private_key_path"}


def rotate_keys(alg: Algorithm = DEFAULT_ALG) -> dict:
    """
    Generate a new keypair, making it the new active signing key.
    The previous private key file is shredded (overwritten with zeros
    before deletion) so its bits cannot be recovered from disk.
    Existing signatures that reference the old key_id remain valid —
    verify_signature() resolves the public key by key_id, not by
    "current active key."
    """
    old_meta = _load_active_key_meta()

    new_meta = generate_keypair(alg)

    if old_meta and old_meta.get("private_key_path"):
        old_priv = old_meta["private_key_path"]
        if os.path.exists(old_priv):
            try:
                size = os.path.getsize(old_priv)
                with open(old_priv, "r+b") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
                os.remove(old_priv)
                logger.info(f"[EVIDENCE_SIGNATURE] Old private key shredded: {old_priv}")
            except Exception as e:
                logger.error(f"[EVIDENCE_SIGNATURE] Failed to shred old private key: {e}")

    return new_meta


def _load_private_key(key_id: str, alg: str):
    """Load the private key object for signing. Internal use only."""
    path = _private_path(key_id, alg)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found: {path}")
    # Verify permissions before reading — refuse to use world-readable key
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"Private key {path} has insecure permissions {oct(mode)}. "
            f"Expected 0o600."
        )
    with open(path, "rb") as f:
        pem = f.read()
    return serialization.load_pem_private_key(pem, password=None)


def _load_public_key_for_id(key_id: str, alg: str):
    """
    Load the public key for a historical key_id.  Used during
    verify_signature() to validate signatures made with older keys
    after rotation.
    """
    path = _public_path(key_id, alg)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Public key not found for key_id={key_id}: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ── Signing ──────────────────────────────────────────────────

def sign_hash(sha256_hex: str,
              evidence_id: Optional[int] = None,
              performed_by: str = "system") -> dict:
    """
    Sign `sha256_hex` (the hex-encoded SHA-256 of an evidence file)
    with the current active private key.

    Stores the signature in the `evidence_signatures` DB table and
    fires SIGNED CoC events if `evidence_id` is provided.

    Returns a dict with signature, algorithm, key_id,
    public_key_fingerprint, signed_at.  Never returns private key
    material.

    Raises RuntimeError if no active key exists (call generate_keypair
    first, or let register_evidence_file call it automatically).
    """
    if not sha256_hex or len(sha256_hex) != 64:
        raise ValueError(f"sha256_hex must be a 64-char hex string, got: {sha256_hex!r}")

    meta = _load_active_key_meta()
    if meta is None:
        raise RuntimeError(
            "No active signing key. Call generate_keypair() first, "
            "or set signing.auto_generate: true in config.yaml."
        )

    key_id = meta["key_id"]
    alg    = meta["algorithm"]
    fp     = meta["public_key_fingerprint"]

    private_key = _load_private_key(key_id, alg)
    payload     = sha256_hex.encode()   # sign the ASCII hex string, not raw bytes

    if alg == "ed25519":
        sig_bytes = private_key.sign(payload)
    elif alg == "rsa4096":
        sig_bytes = private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise ValueError(f"Unknown algorithm in active key metadata: {alg}")

    sig_hex   = sig_bytes.hex()
    signed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    result = {
        "signature":              sig_hex,
        "algorithm":              alg,
        "key_id":                 key_id,
        "public_key_fingerprint": fp,
        "signed_at":              signed_at.isoformat(),
    }

    # Persist to DB
    if evidence_id is not None:
        _persist_signature(evidence_id, sha256_hex, sig_hex, alg, key_id, fp, signed_at)
        # CoC event
        try:
            from core.chain_of_custody import record_event
            record_event(
                evidence_id=evidence_id,
                action="SIGNED",
                performed_by=performed_by,
                reason=f"{alg.upper()} signature applied (key_id={key_id})",
            )
        except Exception:
            pass

    logger.info(
        f"[EVIDENCE_SIGNATURE]\n"
        f"Evidence ID: {evidence_id or 'n/a'}\n"
        f"Algorithm: {alg.upper()}\n"
        f"Status: SIGNED\n"
        f"Timestamp: {signed_at.isoformat()}"
    )
    return result


def _persist_signature(evidence_id: int, sha256_hex: str, sig_hex: str,
                        alg: str, key_id: str, fp: str,
                        signed_at: datetime) -> None:
    """Insert or replace the signature row for this evidence_id."""
    try:
        from database import DbSession, EvidenceSignature
        with DbSession() as s:
            # Replace any existing signature for this evidence_id
            existing = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == evidence_id
            ).first()
            if existing:
                existing.signature              = sig_hex
                existing.algorithm              = alg
                existing.key_id                 = key_id
                existing.public_key_fingerprint = fp
                existing.signed_sha256          = sha256_hex
                existing.signed_at              = signed_at
            else:
                s.add(EvidenceSignature(
                    evidence_id              = evidence_id,
                    signature                = sig_hex,
                    algorithm                = alg,
                    key_id                   = key_id,
                    public_key_fingerprint   = fp,
                    signed_sha256            = sha256_hex,
                    signed_at                = signed_at,
                ))
            s.commit()
    except Exception as e:
        logger.error(f"_persist_signature failed for evidence {evidence_id}: {e}")


# ── Verification ─────────────────────────────────────────────

VerifyResult = Literal["VALID", "INVALID", "MISSING"]


def verify_signature(evidence_id: int,
                     performed_by: str = "system") -> VerifyResult:
    """
    Re-verify the stored signature for `evidence_id`.

    Loads the current sha256_hash from the Evidence row, the
    EvidenceSignature row for this evidence_id, and the public key
    that matches the stored key_id — so this correctly validates
    signatures made with previous keys after rotation.

    Returns "VALID", "INVALID", or "MISSING".

    Fires a SIGNATURE_VERIFIED CoC event (status OK/FAILED) after
    verification regardless of outcome.
    """
    try:
        from database import DbSession, Evidence, EvidenceSignature
        with DbSession() as s:
            ev  = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            sig = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == evidence_id
            ).first()

            if ev is None:
                logger.error(f"[EVIDENCE_SIGNATURE] Evidence ID {evidence_id} not found")
                return "MISSING"

            if sig is None:
                logger.info(
                    f"[EVIDENCE_SIGNATURE]\n"
                    f"Evidence ID: {evidence_id}\n"
                    f"Algorithm: n/a\n"
                    f"Status: MISSING\n"
                    f"Timestamp: {datetime.utcnow().isoformat()}"
                )
                return "MISSING"

            sha256_hex = ev.sha256_hash
            sig_hex    = sig.signature
            alg        = sig.algorithm
            key_id     = sig.key_id

        result = _verify_bytes(sha256_hex, sig_hex, alg, key_id)

    except Exception as e:
        logger.error(f"verify_signature(evidence_id={evidence_id}): {e}")
        result = "INVALID"

    coc_status = "OK" if result == "VALID" else "FAILED"
    logger.info(
        f"[EVIDENCE_SIGNATURE]\n"
        f"Evidence ID: {evidence_id}\n"
        f"Algorithm: {alg.upper() if 'alg' in dir() else 'n/a'}\n"
        f"Status: {result}\n"
        f"Timestamp: {datetime.utcnow().isoformat()}"
    )
    try:
        from core.chain_of_custody import record_event
        record_event(
            evidence_id=evidence_id,
            action="SIGNATURE_VERIFIED",
            performed_by=performed_by,
            reason=f"Cryptographic signature check: {result}",
            status=coc_status,
        )
    except Exception:
        pass

    return result


def _verify_bytes(sha256_hex: str, sig_hex: str,
                  alg: str, key_id: str) -> VerifyResult:
    """
    Core crypto verification — loads the public key for `key_id` and
    checks `sig_hex` against `sha256_hex`.  Returns "VALID" or
    "INVALID" only (never "MISSING" — caller handles that).
    """
    try:
        pub_key  = _load_public_key_for_id(key_id, alg)
        payload  = sha256_hex.encode()
        sig_bytes = bytes.fromhex(sig_hex)

        if alg == "ed25519":
            pub_key.verify(sig_bytes, payload)
        elif alg == "rsa4096":
            pub_key.verify(
                sig_bytes,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            logger.error(f"Unknown algorithm '{alg}' during verification")
            return "INVALID"

        return "VALID"

    except InvalidSignature:
        return "INVALID"
    except FileNotFoundError as e:
        logger.error(f"Public key missing during verification: {e}")
        return "INVALID"
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return "INVALID"
