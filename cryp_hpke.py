from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def simple_hpke_seal(
    pkR: X25519PublicKey,
    info: bytes,                # must be b"MLS 1.0 external init secret"
    plaintext: bytes
) -> tuple[bytes, bytes]:
    skE = X25519PrivateKey.generate()
    pkE = skE.public_key()

    shared = skE.exchange(pkR)

    # ────────────────────────────────────────────────
    #  Critical change: NO suite_id prefix!
    #  MLS uses exactly this info string (no HPKE suite ID)
    full_info = info   # ← just b"MLS 1.0 external init secret"
    # ────────────────────────────────────────────────

    hkdf_extract = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=full_info,
    ).derive(shared)

    key = hkdf_extract[:16]
    nonce = hkdf_extract[16:28]

    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce=nonce, data=plaintext, associated_data=b"")

    kem_output = pkE.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return kem_output, ciphertext

def simple_hpke_open(
    skR_bytes: bytes,                    # ← renamed for clarity: now accepts bytes
    info: bytes,
    kem_output: bytes,
    ciphertext: bytes
) -> bytes:
    """
    HPKE open - accepts raw private key bytes (32 bytes)
    """
    # Convert raw bytes → X25519PrivateKey object
    skR = X25519PrivateKey.from_private_bytes(skR_bytes)
    
    # Reconstruct ephemeral public key
    pkE = X25519PublicKey.from_public_bytes(kem_output)
    
    # ECDH
    shared = skR.exchange(pkE)
    
    # The rest stays exactly the same
    suite_id = b""  # No suite prefix – as per last fix
    full_info = info  # b"MLS 1.0 external init secret"
    
    hkdf_extract = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=full_info,
    ).derive(shared)
    
    key = hkdf_extract[:16]
    nonce = hkdf_extract[16:28]
    
    aead = AESGCM(key)
    try:
        plaintext = aead.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=b""
        )
        return plaintext
    except Exception as e:
        print(f"Decryption failed: {e}")
        print(f"  Derived key (first 8): {key[:8].hex()}")
        print(f"  Nonce: {nonce.hex()}")
        print(f"  Ciphertext len: {len(ciphertext)}")
        raise
