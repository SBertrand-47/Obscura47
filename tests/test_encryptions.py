"""Unit tests for src/core/encryptions.py"""
import json
import pytest
from src.core.encryptions import (
    encrypt_message, decrypt_message,
    ecc_generate_keypair, ecc_load_or_create_keypair,
    onion_encrypt_for_peer, onion_decrypt_with_priv,
    ecdsa_sign, ecdsa_verify,
    aes_gcm_encrypt, aes_gcm_decrypt,
    _pad, _unpad, _cell_size, CELL_BUCKETS, CELL_MAX,
)


# ── Legacy AES-CFB ────────────────────────────────────────────────

class TestLegacyAES:
    def test_roundtrip(self):
        plaintext = "hello world"
        ct = encrypt_message(plaintext)
        assert decrypt_message(ct) == plaintext

    def test_different_ivs(self):
        """Same plaintext should produce different ciphertexts (random IV)."""
        plaintext = "same message"
        assert encrypt_message(plaintext) != encrypt_message(plaintext)

    def test_decrypt_garbage(self):
        assert decrypt_message("not-valid-base64!!!") is None


# ── AES-GCM ───────────────────────────────────────────────────────

class TestAESGCM:
    def test_roundtrip(self):
        key = b"0" * 16
        nonce, ct, tag = aes_gcm_encrypt(key, b"secret")
        assert aes_gcm_decrypt(key, nonce, ct, tag) == b"secret"

    def test_tamper_detection(self):
        """AES-GCM should detect tampering."""
        key = b"0" * 16
        nonce, ct, tag = aes_gcm_encrypt(key, b"secret")
        tampered = bytes([ct[0] ^ 1]) + ct[1:]
        assert aes_gcm_decrypt(key, nonce, tampered, tag) is None

    def test_wrong_key(self):
        key1 = b"0" * 16
        key2 = b"1" * 16
        nonce, ct, tag = aes_gcm_encrypt(key1, b"secret")
        assert aes_gcm_decrypt(key2, nonce, ct, tag) is None


# ── ECC Key Management ────────────────────────────────────────────

class TestECCKeypair:
    def test_generate(self):
        priv, pub_pem = ecc_generate_keypair()
        assert pub_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert priv.curve == "NIST P-256"

    def test_persist_and_load(self, tmp_path):
        key_path = str(tmp_path / "node_key.pem")
        priv1, pub1 = ecc_load_or_create_keypair(key_path)
        priv2, pub2 = ecc_load_or_create_keypair(key_path)
        # Loading should yield the same public key
        assert pub1 == pub2


# ── Onion Encryption (ECDH + AES-GCM) ─────────────────────────────

class TestOnionEncryption:
    def test_roundtrip(self):
        priv, pub = ecc_generate_keypair()
        sealed = onion_encrypt_for_peer(pub, "secret message")
        assert onion_decrypt_with_priv(priv, sealed) == "secret message"

    def test_wrong_key_fails(self):
        priv1, pub1 = ecc_generate_keypair()
        priv2, pub2 = ecc_generate_keypair()
        sealed = onion_encrypt_for_peer(pub1, "secret")
        assert onion_decrypt_with_priv(priv2, sealed) is None

    def test_tamper_detection(self):
        priv, pub = ecc_generate_keypair()
        sealed = onion_encrypt_for_peer(pub, "secret")
        parsed = json.loads(sealed)
        # Corrupt the ciphertext
        parsed["ct"] = "AAAA" + parsed["ct"][4:]
        assert onion_decrypt_with_priv(priv, json.dumps(parsed)) is None

    def test_nested_onion_layers(self):
        """Simulate 3-hop onion routing: encrypt for hop3, then hop2, then hop1."""
        p1, pub1 = ecc_generate_keypair()
        p2, pub2 = ecc_generate_keypair()
        p3, pub3 = ecc_generate_keypair()

        payload = {"data": "final secret"}
        # Innermost: payload wrapped for hop3
        layer3 = onion_encrypt_for_peer(pub3, json.dumps({"payload": payload}))
        # Middle: next_hop=hop3, inner=layer3, wrapped for hop2
        layer2 = onion_encrypt_for_peer(pub2, json.dumps({"next_hop": {"host": "h3"}, "inner": layer3}))
        # Outermost: next_hop=hop2, inner=layer2, wrapped for hop1
        layer1 = onion_encrypt_for_peer(pub1, json.dumps({"next_hop": {"host": "h2"}, "inner": layer2}))

        # Peel layer 1
        decrypted1 = json.loads(onion_decrypt_with_priv(p1, layer1))
        assert decrypted1["next_hop"]["host"] == "h2"
        # Peel layer 2
        decrypted2 = json.loads(onion_decrypt_with_priv(p2, decrypted1["inner"]))
        assert decrypted2["next_hop"]["host"] == "h3"
        # Peel layer 3 (payload)
        decrypted3 = json.loads(onion_decrypt_with_priv(p3, decrypted2["inner"]))
        assert decrypted3["payload"] == payload


# ── Fixed-size cells (traffic-analysis resistance) ────────────────

class TestFixedSizeCells:
    def test_pad_roundtrip_various_lengths(self):
        for n in (0, 1, 50, 511, 512, 513, 8000, 16384, 70000):
            data = b"x" * n
            assert _unpad(_pad(data)) == data

    def test_pad_lands_on_bucket(self):
        """Padded length is always exactly a bucket size (or CELL_MAX multiple)."""
        for n in (0, 1, 200, 600, 9000):
            padded = _pad(b"y" * n)
            assert len(padded) == _cell_size(n + 4)  # +4 length prefix
            assert len(padded) in CELL_BUCKETS or len(padded) % CELL_MAX == 0

    def test_same_bucket_same_wire_length(self):
        """The core property: two payloads in the same bucket are
        byte-length identical on the wire, so ciphertext length leaks
        only the bucket, not the real size."""
        priv, pub = ecc_generate_keypair()
        # 10 bytes and 400 bytes both fall in the 512 bucket
        small = onion_encrypt_for_peer(pub, "a" * 10)
        bigger = onion_encrypt_for_peer(pub, "a" * 400)
        assert len(small) == len(bigger)
        # ciphertext field itself must match in length
        assert len(json.loads(small)["ct"]) == len(json.loads(bigger)["ct"])
        # and both still decrypt correctly
        assert onion_decrypt_with_priv(priv, small) == "a" * 10
        assert onion_decrypt_with_priv(priv, bigger) == "a" * 400

    def test_different_buckets_differ_in_length(self):
        priv, pub = ecc_generate_keypair()
        small = onion_encrypt_for_peer(pub, "a" * 10)       # 512 bucket
        large = onion_encrypt_for_peer(pub, "a" * 3000)     # 8192 bucket
        assert len(large) > len(small)

    def test_corrupt_length_prefix_rejected(self):
        # Length prefix claiming more bytes than the cell holds must raise.
        bad = (9999).to_bytes(4, "big") + b"short"
        with pytest.raises(ValueError):
            _unpad(bad)


# ── ECDSA Sign / Verify ───────────────────────────────────────────

class TestECDSA:
    def test_sign_verify_roundtrip(self):
        priv, pub = ecc_generate_keypair()
        msg = b"challenge nonce"
        sig = ecdsa_sign(priv, msg)
        assert ecdsa_verify(pub, msg, sig) is True

    def test_wrong_message_fails(self):
        priv, pub = ecc_generate_keypair()
        sig = ecdsa_sign(priv, b"original")
        assert ecdsa_verify(pub, b"tampered", sig) is False

    def test_wrong_key_fails(self):
        priv1, pub1 = ecc_generate_keypair()
        priv2, pub2 = ecc_generate_keypair()
        sig = ecdsa_sign(priv1, b"msg")
        assert ecdsa_verify(pub2, b"msg", sig) is False

    def test_malformed_signature(self):
        _, pub = ecc_generate_keypair()
        assert ecdsa_verify(pub, b"msg", "not-base64!") is False

    def test_signatures_differ(self):
        """ECDSA is randomized - same input should produce different signatures."""
        priv, _ = ecc_generate_keypair()
        sig1 = ecdsa_sign(priv, b"msg")
        sig2 = ecdsa_sign(priv, b"msg")
        assert sig1 != sig2
