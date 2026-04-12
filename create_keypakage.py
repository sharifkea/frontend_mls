# test_keypackage.py
import sys
from urllib import response
import requests
from datetime import datetime, timedelta

# Point to the inner package folder
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.MLS._key_package import KeyPackageTBS, KeyPackage
from mls_stuff.RatchetTree._leaf_node import LeafNode, LeafNodePayload, LeafNodeTBS, LeafNodeSource
from mls_stuff.Enums import CipherSuite, ProtocolVersion, CredentialType, LeafNodeSource, KeyType
from mls_stuff.Misc._capabilities import Capabilities
from mls_stuff.Misc._lifetime import Lifetime
from mls_stuff.Crypto import HPKEPublicKey, SignaturePublicKey, Credential
from mls_stuff.Crypto._key_pair import KeyPair
from mls_stuff.Misc import VLBytes
from mls_stuff.Crypto.Credential import BasicCredential
from mls_stuff.Misc import SignContent
from mls_stuff.Crypto import SignWithLabel
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

# ──────────────────────────────────────────────────────────────
#  Helper functions – only change values here once
# ──────────────────────────────────────────────────────────────

def get_ed25519_keys():
    """Generate a fresh Ed25519 keypair and return (priv_bytes, pub_bytes).
    Replace with your real private key bytes if you want to keep it consistent.
    """
# We create via cryptography first (since KeyPair doesn't have .generate())
    raw_priv = ed25519.Ed25519PrivateKey.generate()
    raw_pub = raw_priv.public_key()

    priv_bytes = raw_priv.private_bytes_raw()     # 32 bytes
    pub_bytes  = raw_pub.public_bytes_raw()       # 32 bytes

   #print(f"Raw private key length: {len(priv_bytes)} bytes")
   #print(f"Raw public key length : {len(pub_bytes)} bytes\n")

    # 2. Wrap it in KeyPair
    kp = KeyPair(
        key_type=KeyType.ED25519,
        private_key=priv_bytes,
        public_key=pub_bytes
    )
   
    priv_bytes = kp.private
    pub_bytes  = kp.public
    return priv_bytes, pub_bytes


def get_x25519_pub_bytes():
    raw_priv = x25519.X25519PrivateKey.generate()
    raw_pub = raw_priv.public_key()

    priv_bytes = raw_priv.private_bytes_raw()     # 32 bytes
    pub_bytes  = raw_pub.public_bytes_raw()       # 32 bytes

   #print(f"Raw private key length: {len(priv_bytes)} bytes")
   #print(f"Raw public key length : {len(pub_bytes)} bytes\n")

    return priv_bytes, pub_bytes



# ──────────────────────────────────────────────────────────────
#  Main logic
# ──────────────────────────────────────────────────────────────

def GeneratKeyPackage(user_id: str):
   #print("=== Generating KeyPackage ===\n")

    cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 # same as before

    # 1. Load keys
    ed25519_priv_bytes, ed25519_pub_bytes = get_ed25519_keys()
   #print(f"{user_id}s private Key (hex): {ed25519_priv_bytes.hex()}\n")
    
    x25519_priv_bytes, x25519_pub_bytes = get_x25519_pub_bytes()
   #print(f"X25519 init private key (first 16): {x25519_priv_bytes[:16].hex()}...")
    # 3. Create credential
    if isinstance(user_id, bytes):
        user_id_str = user_id.decode('utf-8')
    else:
        user_id_str = str(user_id)
    identity_vl = VLBytes(bytes(user_id_str, "utf-8") + b"@example.com")
    credential = BasicCredential(credential_type=CredentialType.basic, identity=identity_vl)

    # 4. Key wrappers
    hpke_pub = HPKEPublicKey(x25519_pub_bytes)  # ← Using X25519 public key
    sig_pub = SignaturePublicKey(ed25519_pub_bytes)

    # 4. Capabilities
    caps = Capabilities(
        versions=[ProtocolVersion.MLS10],
        cipher_suites=[cs],
        extensions=[],
        proposals=[],
        credentials=[CredentialType.basic]
    )

    # 5. Lifetime (30 days)
    now = int(datetime.now().timestamp())
    thirty_days_later = now + int(timedelta(days=30).total_seconds())
    lifetime = Lifetime(not_before=now, not_after=thirty_days_later)

    # 6. LeafNodePayload + signing
    payload = LeafNodePayload(
        encryption_key=hpke_pub,
        signature_key=sig_pub,
        credential=credential,
        capabilities=caps,
        leaf_node_source=LeafNodeSource.key_package,
        lifetime=lifetime,
        parent_hash=None,
        extensions=None
    )

    tbs_leaf = LeafNodeTBS(payload=payload)
    signature_leaf = tbs_leaf.signature(cipher_suite=cs, sign_key=ed25519_priv_bytes)
    leaf_node = LeafNode(value=payload, signature=VLBytes(signature_leaf))

   #print("LeafNode created and signed")

    # 7. KeyPackageTBS
    kptbs = KeyPackageTBS(
        version=ProtocolVersion.MLS10,
        cipher_suite=cs,
        init_key=hpke_pub,          # HPKEPublicKey object
        leaf_node=leaf_node,
        extensions=[]
    )

   #print("KeyPackageTBS created")

    # 8. Sign TBS → full KeyPackage
    sign_content = SignContent(b"KeyPackageTBS", kptbs.serialize())
    signature_kp = SignWithLabel(cs, sign_content, ed25519_priv_bytes)

    key_package = KeyPackage(
        content=kptbs,
        signature=VLBytes(signature_kp)
    )

   #print("Full KeyPackage created!")
   #print(f"Signature length: {len(signature_kp)} bytes")

    # 9. Serialize & save
    
    kp_bytes = key_package.serialize()
   #print(f"Full serialized KeyPackage length: {len(kp_bytes)} bytes")
   #print("First 32 bytes (hex):", kp_bytes[:32].hex())
    return ed25519_priv_bytes, x25519_priv_bytes, kp_bytes
   
