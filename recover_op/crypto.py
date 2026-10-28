import base64
import hashlib
import json
import re
from typing import Any, Dict, Optional, Tuple, Union

try:
    from Cryptodome.Cipher import AES, PKCS1_OAEP
    from Cryptodome.Hash import SHA256
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.PublicKey import RSA
except ImportError:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
    from Crypto.PublicKey import RSA


def b64url_decode(s: Union[str, bytes]) -> bytes:
    """Decode URL-safe base64 string, automatically handling missing padding."""
    if isinstance(s, bytes):
        s = s.decode("ascii")
    # Clean whitespace and newlines
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.b64decode((s + pad).encode("ascii"), altchars=b"-_")


def b64url_encode(b: bytes) -> str:
    """Encode bytes to URL-safe base64 string without trailing padding."""
    return base64.b64encode(b, altchars=b"-_").decode("ascii").rstrip("=")


def b64url_to_int(s: Union[str, bytes]) -> int:
    """Decode base64url data directly into a big-endian integer."""
    raw = b64url_decode(s)
    return int.from_bytes(raw, byteorder="big")


def decode_payload(data: Any) -> bytes:
    """
    Attempt to convert data (str, bytes, hex, base64) into raw bytes.
    """
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if not isinstance(data, str):
        data = str(data)
    data = data.strip()

    # Try hex
    try:
        if len(data) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in data):
            return bytes.fromhex(data)
    except Exception:
        pass

    # Try base64url
    try:
        return b64url_decode(data)
    except Exception:
        pass

    # Try standard base64
    try:
        pad = "=" * (-len(data) % 4)
        return base64.b64decode((data + pad).encode("ascii"))
    except Exception:
        pass

    return data.encode("utf-8")


def compute_2skd(
    secret_key: str,
    master_password: str,
    email: str,
    p2salt: bytes,
    iterations: int,
    algorithm: Union[str, bytes],
) -> bytes:
    """
    1Password Two-Secret Key Derivation (2SKD).
    Derives the Master Unlock Key (MUK) from Master Password + Secret Key.
    """
    # Clean secret key
    sk = secret_key.strip().upper()
    version = sk[0:2]
    account_id = sk[3:9]
    secret = re.sub(r"-", "", sk[10:])

    email_bytes = email.strip().lower().encode("utf-8")
    account_id_bytes = account_id.encode("utf-8")
    secret_bytes = secret.encode("utf-8")

    if isinstance(algorithm, str):
        algorithm_bytes = algorithm.encode("utf-8")
    else:
        algorithm_bytes = algorithm

    # 1. HKDF with email and algorithm to get password salt
    hkdf_pass_salt = HKDF(
        master=p2salt,
        key_len=32,
        salt=email_bytes,
        hashmod=SHA256,
        num_keys=1,
        context=algorithm_bytes,
    )

    # 2. PBKDF2 stretching of master password
    password_bytes = master_password.encode("utf-8")
    password_key = hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        hkdf_pass_salt,
        iterations,
        dklen=32,
    )

    # 3. HKDF of account secret key
    hkdf_key = HKDF(
        master=secret_bytes,
        key_len=32,
        salt=account_id_bytes,
        hashmod=SHA256,
        num_keys=1,
        context=b"A3",
    )

    # 4. XOR combination
    muk = bytes([a ^ b for a, b in zip(password_key, hkdf_key)])
    return muk


def dec_aes_gcm(ciphertext_with_tag: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext. The last 16 bytes are the GCM authentication tag.
    """
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short to contain 16-byte GCM tag")
    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    return cipher.decrypt_and_verify(ct, tag)


def parse_rsa_jwk(jwk_data: Union[str, bytes, Dict[str, Any]]) -> RSA.RsaKey:
    """
    Pure Python parser to load RSA Private Key from JWK structure
    without needing the outdated pyjwkest library.
    """
    if isinstance(jwk_data, (bytes, bytearray)):
        jwk_data = jwk_data.decode("utf-8")
    if isinstance(jwk_data, str):
        # Handle wrapped {"keys": [...]} or raw JWK
        parsed = json.loads(jwk_data)
        if isinstance(parsed, dict) and "keys" in parsed and len(parsed["keys"]) > 0:
            key_dict = parsed["keys"][0]
        else:
            key_dict = parsed
    else:
        key_dict = jwk_data

    n = b64url_to_int(key_dict["n"])
    e = b64url_to_int(key_dict["e"])
    d = b64url_to_int(key_dict["d"])

    if "p" in key_dict and "q" in key_dict:
        p = b64url_to_int(key_dict["p"])
        q = b64url_to_int(key_dict["q"])
        return RSA.construct((n, e, d, p, q))
    return RSA.construct((n, e, d))


def dec_rsa_oaep(rsa_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext using the private RSA key.
    """
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext)
