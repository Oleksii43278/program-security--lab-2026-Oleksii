import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALG_NAME = "X25519-HKDF-SHA256-AES256GCM"
HKDF_INFO = b"gm-hub/session-report/v1"


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_recipient_keypair() -> tuple[X25519PrivateKey, str, str]:
    priv = X25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    kid = hashlib.sha256(pub_raw).hexdigest()[:16]
    return priv, pub_b64, kid


def encrypt_session_payload(plaintext_obj: dict, recipient_pub_b64: str, kid: str, meta: dict) -> dict:
    recipient_raw = base64.b64decode(recipient_pub_b64)
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_raw)

    eph_priv = X25519PrivateKey.generate()
    eph_raw = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    shared = eph_priv.exchange(recipient_pub)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_raw + recipient_raw,
        info=HKDF_INFO,
    ).derive(shared)

    nonce = os.urandom(12)
    aad = canonical_bytes(meta)
    ciphertext = AESGCM(aes_key).encrypt(nonce, canonical_bytes(plaintext_obj), aad)

    return {
        "v": 1,
        "alg": ALG_NAME,
        "kid": kid,
        "epk": base64.b64encode(eph_raw).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
        "meta": meta,
    }


def decrypt_session_payload(envelope: dict, recipient_priv: X25519PrivateKey) -> dict:
    if envelope.get("alg") != ALG_NAME:
        raise ValueError("Unsupported E2EE algorithm")
    eph_raw = base64.b64decode(envelope["epk"])
    recipient_raw = recipient_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    eph_pub = X25519PublicKey.from_public_bytes(eph_raw)
    shared = recipient_priv.exchange(eph_pub)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_raw + recipient_raw,
        info=HKDF_INFO,
    ).derive(shared)

    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ct"])
    aad = canonical_bytes(envelope["meta"])
    pt = AESGCM(aes_key).decrypt(nonce, ct, aad)
    return json.loads(pt.decode("utf-8"))