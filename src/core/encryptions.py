import os
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


# NOTE: Demo-only symmetric key. For production, use per-hop ephemeral keys.
AES_KEY = os.urandom(16)


def encrypt_message(message: str, key: bytes = AES_KEY) -> str:
    """
    Encrypt a plaintext string using AES (CFB) with a random IV.
    Returns a base64-encoded string containing IV + ciphertext.
    """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(iv + encrypted).decode()


def decrypt_message(encrypted_message: str, key: bytes = AES_KEY) -> str | None:
    """
    Decrypt a base64-encoded string that contains IV + ciphertext.
    Returns the plaintext string, or None if decryption fails.
    """
    try:
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        encrypted_data = data[16:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(encrypted_data).decode()
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        return None


# --- ECC ECDH + AES-GCM (per-hop sealing) ---

def ecc_generate_keypair():
    priv = ECC.generate(curve='P-256')
    pub_pem = priv.public_key().export_key(format='PEM')
    return priv, pub_pem


def _ecc_load_public(pem: str):
    return ECC.import_key(pem)


def _derive_symmetric_key(priv: ECC.EccKey, peer_pub_pem: str) -> bytes:
    peer = _ecc_load_public(peer_pub_pem)
    # ECDH via shared secret = priv.d * peer_pub
    shared_point = peer.pointQ * priv.d
    # Use x-coordinate as input to HKDF
    shared_x = int(shared_point.x).to_bytes(32, 'big')
    key = HKDF(shared_x, 32, b'obscura47-ecdh', SHA256)
    return key


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        return None


def onion_encrypt_for_peer(peer_pub_pem: str, plaintext: str) -> str:
    eph_priv, eph_pub_pem = ecc_generate_keypair()
    key = _derive_symmetric_key(eph_priv, peer_pub_pem)
    nonce, ct, tag = aes_gcm_encrypt(key, plaintext.encode())
    sealed = {
        'epub': eph_pub_pem,
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ct': base64.b64encode(ct).decode(),
    }
    # Store as JSON string
    import json as _json
    return _json.dumps(sealed)


def onion_decrypt_with_priv(priv: ECC.EccKey, sealed_json: str) -> str | None:
    try:
        import json as _json
        sealed = _json.loads(sealed_json)
        peer_pub_pem = sealed['epub']
        key = _derive_symmetric_key(priv, peer_pub_pem)
        nonce = base64.b64decode(sealed['nonce'])
        tag = base64.b64decode(sealed['tag'])
        ct = base64.b64decode(sealed['ct'])
        pt = aes_gcm_decrypt(key, nonce, ct, tag)
        return pt.decode() if pt is not None else None
    except Exception:
        return None



# --- Persistent ECC key utilities for roles ---

def _expand(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def ecc_load_or_create_keypair(key_path: str) -> tuple[ECC.EccKey, str]:
    """
    Load an ECC private key from key_path or create and persist a new one.
    Returns (private_key_obj, public_key_pem).
    """
    key_path = _expand(key_path)
    key_dir = os.path.dirname(key_path)
    try:
        if key_dir and not os.path.isdir(key_dir):
            os.makedirs(key_dir, exist_ok=True)
    except Exception:
        pass

    if os.path.isfile(key_path):
        try:
            with open(key_path, 'r', encoding='utf-8') as f:
                priv = ECC.import_key(f.read())
            return priv, priv.public_key().export_key(format='PEM')
        except Exception:
            # fall through to regenerate
            pass

    priv = ECC.generate(curve='P-256')
    try:
        with open(key_path, 'w', encoding='utf-8') as f:
            f.write(priv.export_key(format='PEM'))
    except Exception:
        pass
    return priv, priv.public_key().export_key(format='PEM')

