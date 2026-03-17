from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def simple_hpke_seal(
    pkR,                        # X25519PublicKey from KeyPackage init_key
    info: bytes,                # e.g. b"MLS 1.0 external init secret"
    plaintext: bytes
) -> tuple[bytes, bytes]:
    skE = X25519PrivateKey.generate()
    pkE = skE.public_key()

    shared = skE.exchange(pkR)

    # MLS HPKE uses labeled extract/expand with suite ID
    suite_id = b"HPKE-v1-X25519-SHA256-AES128GCM"   # exact string from RFC 9180 for this suite
    full_info = suite_id + info

    # Extract (no salt) + expand to key + nonce
    hkdf_extract = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                  # arbitrary expand length, we take what we need
        salt=None,
        info=full_info,
    ).derive(shared)

    # In real HPKE: separate keys for different labels, but for base mode this approximates
    key = hkdf_extract[:16]         # AES-128 key
    nonce = hkdf_extract[16:28]     # 12-byte nonce for GCM

    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce=nonce, data=plaintext, associated_data=b"")

    # KEM output: raw 32-byte X25519 public key (MLS expects Raw format)
    kem_output = pkE.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return kem_output, ciphertext
def simple_hpke_open(
    skR,                        # X25519PrivateKey from KeyPackage init_key
    info: bytes,                # same info used in seal
    kem_output: bytes,          # 32-byte X25519 public key from seal
    ciphertext: bytes           # from seal
) -> bytes:
    pkE = X25519PublicKey.from_public_bytes(kem_output)
    shared = skR.exchange(pkE)

    suite_id = b"HPKE-v1-X25519-SHA256-AES128GCM"
    full_info = suite_id + info

    hkdf_extract = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=full_info,
    ).derive(shared)

    key = hkdf_extract[:16]
    nonce = hkdf_extract[16:28]

    aead = AESGCM(key)
    plaintext = aead.decrypt(nonce=nonce, data=ciphertext, associated_data=b"")

    return plaintext