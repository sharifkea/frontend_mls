# api_client.py
import cryptography, base64, requests, sys, secrets, hashlib, time, api_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryp_hpke import simple_hpke_seal, simple_hpke_open
from flask import session

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.RatchetTree import RatchetTree, RatchetNode, LeafNode
#from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, SenderType, ContentType, WireFormat, ExtensionType
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._proposal import Add
from mls_stuff.MLS._commit import Commit
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.MLS import MLSMessage, Sender, AuthenticatedContent, FramedContent, FramedContentAuthData
from mls_stuff.Misc import VLBytes, SignContent, KDFLabel, Extension
from mls_stuff.Crypto._crypt_with_label import SignWithLabel
from mls_stuff.Crypto import GroupSecrets, EncryptedGroupSecrets, HPKECiphertext, ExtractWelcomeSecret, ExpandWithLabel, ExtractPSKSecret
from mls_stuff.Objects import GroupContext, GroupInfo
from mls_stuff.Crypto._derive_secrets import DeriveSecret
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

BASE_URL = "http://localhost:8000"  # Your FastAPI backend URL

class MessageRatchet:
    """Per-message ratchet for forward secrecy and PCS"""
    
    def __init__(self, cipher_suite, root_secret):
        self.cipher_suite = cipher_suite
        self.root_secret = root_secret
        self.message_count = 0
        self.current_key = None
    
    def next_key(self):
        """Generate next message key using KDF chain"""
        label = f"message {self.message_count}".encode()
        self.current_key = DeriveSecret(self.cipher_suite, self.root_secret, label)
        self.message_count += 1
        return self.current_key

def encrypt_with_ratchet(group_state, message_text, sender_leaf_index):
    """Encrypt message with ratcheted key for PCS"""
    tree = group_state['tree']
    cipher_suite = group_state['cipher_suite']
    
    # Derive root_secret from tree
    root_secret = tree.hash(cipher_suite)
    
    # Initialize or advance ratchet
    if 'ratchet' not in group_state:
        group_state['ratchet'] = MessageRatchet(cipher_suite, root_secret)
    
    # Get next message key
    message_key = group_state['ratchet'].next_key()
    
    # Encrypt with this unique key
    nonce = secrets.token_bytes(12)
    aead = AESGCM(message_key)
    
    # Create FramedContent
    group_id_bytes = base64.b64decode(group_state['group_id_b64'])
    sender = Sender(sender_type=SenderType.member, leaf_index=sender_leaf_index)
    
    framed_content = FramedContent(
        group_id=VLBytes(group_id_bytes),
        epoch=group_state['epoch'],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.application,
        application_data=VLBytes(message_text.encode('utf-8'))
    )
    
    content_bytes = framed_content.serialize()
    ciphertext = aead.encrypt(nonce, content_bytes, b"")
    
    # Store the generation number for decryption
    generation = group_state['ratchet'].message_count - 1
    
    return ciphertext, nonce, generation

def add_member(group, new_member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    """
    Create a Commit + Welcome to add a new member to the group.
    Returns the Welcome bytes and updated group.
    """
    print(f"\n=== Adding {new_member_id} to group ===\n")

    # Ensure group_id_b64 exists
    if 'group_id_b64' not in group and 'group_id' in group:
        group_id_bytes = group['group_id'].data
        group['group_id_b64'] = base64.b64encode(group_id_bytes).decode('ascii')

    # 1. Fetch new member's KeyPackage
    new_kp_bytes = api_client.get_latest_keypackage(new_member_id)
    if not new_kp_bytes:
        print("Cannot add - KeyPackage not found")
        return None, group

    new_kp = KeyPackage.deserialize(bytearray(new_kp_bytes))
    new_leaf = new_kp.content.leaf_node

    # 2. Create Add proposal
    add_proposal = Add(key_package=new_kp)

    # 3. Create Commit
    commit = Commit(proposals=[add_proposal], path=None)

    # 4. Build FramedContent + AuthenticatedContent
    sender = Sender(sender_type=SenderType.member, leaf_index=committer_index)
    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.commit,
        commit=commit
    )

    auth = FramedContentAuthData(signature=VLBytes(b""), confirmation_tag=None)
    authenticated_content = AuthenticatedContent(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        content=framed_content,
        auth=auth
    )

    # 5. Sign the commit
    tbs = authenticated_content.FramedContentTBS(group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature_bytes = SignWithLabel(cs, sign_content, committer_priv_bytes)
    authenticated_content.auth.signature = VLBytes(signature_bytes)

    # 6. Create MLS PublicMessage (the Commit)
    public_commit = MLSMessage(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        msg_content=authenticated_content
    )

    # 7. Add new leaf to the tree
    tree: RatchetTree = group["tree"]
    new_leaf_index = len(tree.leaves)

    # Extend tree if needed
    while tree.nodes <= new_leaf_index * 2:
        tree.extend()

    # Add the new leaf
    tree[new_leaf_index] = new_leaf
    tree[new_leaf_index]._leaf_index = new_leaf_index
    
    # Update indices
    tree.update_node_index()
    tree.update_leaf_index()
    
    # Fix all leaf indices
    for i in range(len(tree.leaves)):
        if isinstance(tree.leaves[i], LeafNode):
            tree.leaves[i]._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()

    # 8. Derive new secrets for the NEXT epoch
    old_init_secret = group.get("init_secret")
    commit_secret = bytes(32)

    joiner_secret = group["group_context"].extract_joiner_secret(old_init_secret, commit_secret)
    psk_secret = bytes(32)

    new_epoch_secret = group["group_context"].extract_epoch_secret(joiner_secret, psk_secret)
    new_init_secret = DeriveSecret(cs, new_epoch_secret, b"init")

    # 9. Create NEW GroupContext for the NEXT epoch
    new_group_context = GroupContext(
        cipher_suite=group["group_context"].cipher_suite,
        group_id=group["group_context"].group_id,
        epoch=group["epoch"] + 1,
        tree_hash=VLBytes(tree.hash(cs)),
        confirmed_transcript_hash=group["group_context"].confirmed_transcript_hash,
        extensions=group["group_context"].extensions
    )

    # 10. Create ratchet_tree extension with the COMPLETE tree
    ratchet_tree_extension = Extension(
        extension_type=ExtensionType.ratchet_tree,
        extension_data=VLBytes(tree.serialize())
    )

    # 11. Build GroupInfo with NEW group context
    confirmed_data = b"confirmation" + authenticated_content.serialize()
    confirmation_tag = hashlib.sha256(confirmed_data).digest()

    group_info = GroupInfo(
        group_context=new_group_context,
        confirmation_tag=VLBytes(confirmation_tag),
        signer=committer_index,
        signature=VLBytes(b""),
        extensions=[ratchet_tree_extension]
    )

    # 12. Prepare GroupSecrets for the new member (send joiner_secret and epoch_secret)
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),
        psks=[],
        path_secret=None
    )
    group_secrets_bytes = group_secrets.serialize()

    # 13. HPKE encrypt GroupSecrets to new member's init key
    init_pub = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(
        bytes(new_kp.content.init_key.data)
    )

    kem_output, ciphertext = simple_hpke_seal(
        init_pub,
        b"MLS 1.0 external init secret",
        group_secrets_bytes
    )

    encrypted_group_secrets = EncryptedGroupSecrets(
        new_member=VLBytes(new_kp.reference_hash(cs)),
        encrypted_group_secrets=HPKECiphertext(
            kem_output=VLBytes(kem_output),
            ciphertext=VLBytes(ciphertext)
        )
    )

    # 14. Encrypt GroupInfo using welcome_secret
    welcome_secret = ExtractWelcomeSecret(cs, joiner_secret, psk_secret)

    AEAD_KEY_SIZE = 16
    AEAD_NONCE_SIZE = 12

    nonce_label = KDFLabel(AEAD_NONCE_SIZE, b"nonce")
    key_label = KDFLabel(AEAD_KEY_SIZE, b"key")

    welcome_nonce = ExpandWithLabel(cs, welcome_secret, nonce_label)
    welcome_key = ExpandWithLabel(cs, welcome_secret, key_label)

    aead = AESGCM(welcome_key)
    encrypted_group_info_cipher = aead.encrypt(
        nonce=welcome_nonce,
        data=group_info.serialize(),
        associated_data=b""
    )

    # 15. Build final Welcome
    welcome = Welcome(
        cipher_suite=cs,
        secrets=[encrypted_group_secrets],
        encrypted_group_info=VLBytes(encrypted_group_info_cipher)
    )

    welcome_message = MLSMessage(
        wire_format=WireFormat.MLS_WELCOME,
        msg_content=welcome
    )
    welcome_bytes = welcome_message.serialize()

    # 16. Prepare updated group state
    updated_group = {
        "group_id": group["group_id"],
        "group_id_b64": group.get("group_id_b64"),
        "epoch": group["epoch"] + 1,
        "tree": tree,
        "group_context": new_group_context,
        "epoch_secret": new_epoch_secret,
        "init_secret": new_init_secret,
        "members": group["members"] + [new_member_id],
    }

    group.update(updated_group)

    print(f"✅ Welcome created successfully")
    print(f"   New epoch: {updated_group['epoch']}, New leaf index: {new_leaf_index}")
    print(f"   Tree has {len(tree.leaves)} leaves, {tree.nodes} nodes")

    return welcome_bytes, updated_group

def derive_epoch_secret_from_tree(tree: RatchetTree, cipher_suite: CipherSuite) -> bytes:
    """Derive epoch secret from a properly repaired tree"""
    if tree is None:
        raise ValueError("No tree provided")
    
    print(f"\n{'='*60}")
    print(f"🌲 DERIVING EPOCH SECRET FROM TREE")
    print(f"{'='*60}")
    print(f"   Tree leaves: {len(tree.leaves)}")
    print(f"   Tree nodes: {tree.nodes}")
    
    # Print tree hash BEFORE any fixes
    try:
        original_hash = tree.hash(cipher_suite)
        print(f"   Original tree hash (first 16): {original_hash[:16].hex()}")
    except Exception as e:
        print(f"   Original tree hash: ERROR - {e}")
    
    # ===== FORCE leaf indices for ALL leaves =====
    print(f"\n📊 Fixing leaf indices...")
    for i, leaf in enumerate(tree.leaves):
        if isinstance(leaf, LeafNode):
            if not hasattr(leaf, '_leaf_index') or leaf._leaf_index is None:
                leaf._leaf_index = i
                print(f"   Fixed leaf {i}: set _leaf_index = {leaf._leaf_index}")
            else:
                print(f"   Leaf {i}: _leaf_index = {leaf._leaf_index}")
    
    # Also ensure node indices
    for i in range(tree.nodes):
        node = tree[i]
        if hasattr(node, '_node_index'):
            if node._node_index is None:
                node._node_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Print tree hash AFTER fixes
    try:
        fixed_hash = tree.hash(cipher_suite)
        print(f"\n   Fixed tree hash (first 16): {fixed_hash[:16].hex()}")
    except Exception as e:
        print(f"   Fixed tree hash: ERROR - {e}")
        raise
    
    # Derive epoch secret
    root_secret = tree.hash(cipher_suite)
    epoch_secret = DeriveSecret(cipher_suite, root_secret, b"epoch")
    
    print(f"\n   root_secret (first 8): {root_secret[:8].hex()}")
    print(f"   epoch_secret (first 8): {epoch_secret[:8].hex()}")
    print(f"{'='*60}\n")
    
    return epoch_secret
