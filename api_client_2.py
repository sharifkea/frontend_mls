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


class Ratchet:
    """
    Single ratchet chain for one direction between two users.
    Each step produces a new message key AND a new root secret.
    This provides forward secrecy - compromising current state doesn't reveal past keys.
    """
    
    def __init__(self, root_secret: bytes, cipher_suite):
        self.cipher_suite = cipher_suite
        self.root_secret = root_secret
        self.generation = 0
        self.current_key = None
    
    def next_key(self) -> tuple[bytes, int]:
        """
        Advance the ratchet and return the next message key.
        Returns: (message_key, generation)
        """
        # Derive 64 bytes: first 32 = message key, next 32 = new root
        output = DeriveSecret(self.cipher_suite, self.root_secret, b"ratchet_step")
        
        message_key = output[:32]
        self.root_secret = output[32:64]  # Update root for next step
        
        generation = self.generation
        self.generation += 1
        self.current_key = message_key
        
        print(f"   🔄 Ratchet advanced: gen {generation}, key: {message_key[:8].hex()}...")
        return message_key, generation
    
    def get_key_for_generation(self, target_generation: int) -> bytes:
        """
        Fast-forward ratchet to a specific generation and return that key.
        Used for decryption when receiving out-of-order messages.
        """
        if target_generation < self.generation:
            # This should not happen with proper MLS ordering
            # But if it does, we can't go backwards (forward secrecy)
            raise ValueError(f"Cannot go backwards: have gen {self.generation}, requested {target_generation}")
        
        # Fast-forward to target
        current_key = None
        for _ in range(self.generation, target_generation + 1):
            current_key, _ = self.next_key()
        
        return current_key
    
    def get_current_generation(self) -> int:
        return self.generation
    
    def to_dict(self) -> dict:
        """Serialize for storage in user_crypto_store"""
        return {
            'root_secret': base64.b64encode(self.root_secret).decode('ascii'),
            'generation': self.generation,
            'cipher_suite': str(self.cipher_suite)
        }
    
    @classmethod
    def from_dict(cls, data: dict, cipher_suite):
        """Deserialize from stored dict"""
        ratchet = cls(base64.b64decode(data['root_secret']), cipher_suite)
        ratchet.generation = data['generation']
        return ratchet


class PerUserRatchetManager:
    """
    Manages all ratchets for a user in a specific group.
    - One SEND ratchet (for messages this user sends to the group)
    - One RECEIVE ratchet per other user (for messages received from each sender)
    """
    
    def __init__(self, initial_root_secret: bytes, cipher_suite, my_user_id: str):
        self.cipher_suite = cipher_suite
        self.my_user_id = my_user_id
        self.send_ratchet = Ratchet(initial_root_secret, cipher_suite)
        self.recv_ratchets = {}  # sender_user_id -> Ratchet
        self.initial_root = initial_root_secret
    
    def get_send_key(self) -> tuple[bytes, int]:
        """Get next key for sending a message"""
        return self.send_ratchet.next_key()
    
    def get_recv_key(self, sender_user_id: str, generation: int) -> bytes:
        """
        Get key for decrypting a message from a specific sender.
        Creates a new ratchet for that sender if it doesn't exist.
        """
        if sender_user_id not in self.recv_ratchets:
            # Initialize with the same initial root (all start same)
            self.recv_ratchets[sender_user_id] = Ratchet(self.initial_root, self.cipher_suite)
            print(f"   📌 Created receive ratchet for sender {sender_user_id[:8]}...")
        
        ratchet = self.recv_ratchets[sender_user_id]
        return ratchet.get_key_for_generation(generation)
    
    def get_recv_ratchet_state(self, sender_user_id: str) -> dict:
        """Get state of a receive ratchet for debugging"""
        if sender_user_id in self.recv_ratchets:
            return {
                'generation': self.recv_ratchets[sender_user_id].generation
            }
        return None
    
    def to_dict(self) -> dict:
        """Serialize all ratchets for storage"""
        return {
            'send_ratchet': self.send_ratchet.to_dict(),
            'recv_ratchets': {
                sender_id: ratchet.to_dict() 
                for sender_id, ratchet in self.recv_ratchets.items()
            },
            'initial_root': base64.b64encode(self.initial_root).decode('ascii')
        }
    
    @classmethod
    def from_dict(cls, data: dict, cipher_suite, my_user_id: str):
        """Deserialize ratchets from stored dict"""
        initial_root = base64.b64decode(data['initial_root'])
        manager = cls(initial_root, cipher_suite, my_user_id)
        
        # Restore send ratchet
        manager.send_ratchet = Ratchet.from_dict(data['send_ratchet'], cipher_suite)
        
        # Restore receive ratchets
        for sender_id, ratchet_data in data['recv_ratchets'].items():
            manager.recv_ratchets[sender_id] = Ratchet.from_dict(ratchet_data, cipher_suite)
        
        return manager
    
def encrypt_with_ratchet(group_state, message_text: str, sender_user_id: str) -> tuple[str, str, int, int]:
    """
    Encrypt message using the send ratchet.
    Returns: (ciphertext_b64, nonce_b64, generation, sender_leaf_index)
    """
    tree = group_state.get('tree')
    cipher_suite = group_state.get('cipher_suite')
    group_id_b64 = group_state.get('group_id_b64')
    epoch = group_state.get('epoch', 0)
    my_leaf_index = group_state.get('my_leaf_index')  # ← Get from group_state
    
    if my_leaf_index is None:
        raise ValueError("my_leaf_index not found in group_state")
    
    # Get or create ratchet manager
    if 'ratchet_manager' not in group_state:
        # Need root_secret to initialize ratchets
        if 'root_secret' not in group_state:
            # Derive from tree
            _, root_secret = derive_epoch_secret_from_tree(tree, cipher_suite)
            group_state['root_secret'] = root_secret
        
        group_state['ratchet_manager'] = PerUserRatchetManager(
            group_state['root_secret'], 
            cipher_suite, 
            sender_user_id
        )
        print(f"   🔄 Initialized ratchet manager for user {sender_user_id[:8]}...")
    
    manager = group_state['ratchet_manager']
    
    # Get next send key
    message_key, generation = manager.get_send_key()
    print(f"   🔐 Encrypting with send ratchet: generation {generation}, leaf {my_leaf_index}")
    
    # Create FramedContent
    group_id_bytes = base64.b64decode(group_id_b64)
    sender = Sender(sender_type=SenderType.member, leaf_index=my_leaf_index)  # ← Use my_leaf_index
    
    framed_content = FramedContent(
        group_id=VLBytes(group_id_bytes),
        epoch=epoch,
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.application,
        application_data=VLBytes(message_text.encode('utf-8'))
    )
    
    content_bytes = framed_content.serialize()
    
    # Encrypt
    nonce = secrets.token_bytes(12)
    aead = AESGCM(message_key)
    ciphertext = aead.encrypt(nonce, content_bytes, b"")
    
    return (
        base64.b64encode(ciphertext).decode('ascii'),
        base64.b64encode(nonce).decode('ascii'),
        generation,
        my_leaf_index 
    )

def decrypt_with_ratchet(msg_data: dict, group_state: dict, my_user_id: str) -> dict:
    """
    Decrypt a message using the appropriate receive ratchet for the sender.
    """
    cipher_suite = group_state.get('cipher_suite')
    sender_user_id = msg_data.get('sender_user_id')
    generation = msg_data.get('message_generation', 0)
    epoch = msg_data.get('epoch', group_state.get('epoch', 0))
    
    print(f"   🔓 Decrypting: sender={sender_user_id[:8]}..., gen={generation}")
    
    # Get or create ratchet manager
    if 'ratchet_manager' not in group_state:
        # Need root_secret to initialize
        tree = group_state.get('tree')
        if tree is None:
            raise ValueError("No tree in group_state")
        
        epoch_secret, root_secret = derive_epoch_secret_from_tree(tree, cipher_suite)
        group_state['root_secret'] = root_secret
        group_state['ratchet_manager'] = PerUserRatchetManager(
            root_secret, cipher_suite, my_user_id
        )
        print(f"   🔄 Initialized ratchet manager for decryption")
    
    manager = group_state['ratchet_manager']
    
    # Get key from sender's receive ratchet
    message_key = manager.get_recv_key(sender_user_id, generation)
    print(f"   🔑 Got key for gen {generation}: {message_key[:8].hex()}...")
    
    # Decrypt
    ciphertext = base64.b64decode(msg_data['ciphertext'])
    nonce = base64.b64decode(msg_data['nonce'])
    
    aead = AESGCM(message_key)
    plaintext = aead.decrypt(nonce, ciphertext, b"")
    
    # Parse FramedContent
    framed = FramedContent.deserialize(bytearray(plaintext))
    
    if hasattr(framed, 'application_data'):
        message_text = framed.application_data.data.decode('utf-8')
    else:
        message_text = "[No text]"
    
    return {
        'message_id': msg_data.get('message_id'),
        'sender_username': msg_data.get('sender_username', 'Unknown'),
        'sender_leaf_index': framed.sender.leaf_index,
        'text': message_text,
        'epoch': epoch,
        'generation': generation,
        'created_at': msg_data.get('created_at')
    }

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

def derive_epoch_secret_from_tree(tree: RatchetTree, cipher_suite: CipherSuite) -> tuple[bytes, bytes]:
    """
    Derive both epoch_secret and root_secret from tree.
    Returns: (epoch_secret, root_secret)
    """
    if tree is None:
        raise ValueError("No tree provided")
    
    print(f"\n{'='*60}")
    print(f"🌲 DERIVING SECRETS FROM TREE")
    print(f"{'='*60}")
    print(f"   Tree leaves: {len(tree.leaves)}")
    print(f"   Tree nodes: {tree.nodes}")
    
    # Force leaf indices for ALL leaves
    for i, leaf in enumerate(tree.leaves):
        if isinstance(leaf, LeafNode):
            if not hasattr(leaf, '_leaf_index') or leaf._leaf_index is None:
                leaf._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Derive root_secret from tree hash
    root_secret = tree.hash(cipher_suite)
    epoch_secret = DeriveSecret(cipher_suite, root_secret, b"epoch")
    
    print(f"\n   root_secret (first 8): {root_secret[:8].hex()}")
    print(f"   epoch_secret (first 8): {epoch_secret[:8].hex()}")
    print(f"{'='*60}\n")
    
    return epoch_secret, root_secret


def repair_tree_indices(tree: RatchetTree, members_data: list = None) -> RatchetTree:
    """Strong repair to ensure every LeafNode has _leaf_index set"""
    if tree is None:
        return tree

    print(f"=== STRONG TREE REPAIR ===")
    print(f"Tree has {len(tree.leaves)} leaves, {tree.nodes} nodes")
    
    # Method 1: Force sequential indices on all leaves
    for i in range(len(tree.leaves)):
        leaf = tree.leaves[i]
        if isinstance(leaf, LeafNode):
            leaf._leaf_index = i
            print(f"  Set leaf[{i}]._leaf_index = {leaf._leaf_index}")
    
    # Method 2: Also try to set from members_data if provided
    if members_data:
        print(f"Using {len(members_data)} members from database")
        # Create a mapping of user_id to leaf_index
        member_map = {}
        for member in members_data:
            user_id = member.get('user_id')
            leaf_index = member.get('leaf_index')
            if user_id and leaf_index is not None:
                member_map[user_id] = leaf_index
        
        # Try to match leaves by their user_id (if you can extract it)
        # This is complex - you'd need to get the user_id from the leaf node
    
    # Method 3: Recursively fix all nodes in the tree
    def fix_node(node, expected_index=0):
        if node is None:
            return
        if hasattr(node, '_node_index'):
            node._node_index = expected_index
        if hasattr(node, '_leaf_index') and node._leaf_index is None:
            node._leaf_index = expected_index
        if hasattr(node, 'left_node'):
            fix_node(node.left_node, expected_index * 2)
        if hasattr(node, 'right_node'):
            fix_node(node.right_node, expected_index * 2 + 1)
    
    fix_node(tree.root)
    
    # Final library update
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Verify repair worked
    for i, leaf in enumerate(tree.leaves):
        if isinstance(leaf, LeafNode):
            if not hasattr(leaf, '_leaf_index') or leaf._leaf_index is None:
                leaf._leaf_index = i
                print(f"  Emergency fix: leaf[{i}]._leaf_index = {i}")
    
    print(f"✅ Tree repair completed")
    return tree

def get_tree_hash(tree: RatchetTree, cipher_suite: CipherSuite) -> str:
    """Compute and return tree hash for comparison"""
    if tree is None:
        return "None"
    try:
        tree_hash = tree.hash(cipher_suite)
        return tree_hash.hex()
    except Exception as e:
        return f"Error: {e}"

def get_tree_details(tree: RatchetTree, cipher_suite: CipherSuite) -> dict:
    """Get detailed tree information for debugging"""
    if tree is None:
        return {"error": "Tree is None"}
    
    details = {
        "leaves_count": len(tree.leaves),
        "nodes_count": tree.nodes,
        "tree_hash": get_tree_hash(tree, cipher_suite),
        "leaves_info": []
    }
    
    for i, leaf in enumerate(tree.leaves):
        if isinstance(leaf, LeafNode):
            leaf_info = {
                "index": i,
                "has_leaf_index": hasattr(leaf, '_leaf_index'),
                "leaf_index_value": leaf._leaf_index if hasattr(leaf, '_leaf_index') else None,
                "has_encryption_key": hasattr(leaf, 'encryption_key') and leaf.encryption_key is not None,
                "has_signature_key": hasattr(leaf, 'signature_key') and leaf.signature_key is not None,
            }
            details["leaves_info"].append(leaf_info)
    
    return details

def add_member_to_tree_only(group, new_member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    """
    Add a member to the tree WITHOUT creating a Welcome message.
    This updates the tree and epoch but does NOT generate a Welcome.
    """
    print(f"   Adding {new_member_id} to tree (no welcome yet)")

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

    # 6. Add new leaf to the tree
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

    # 7. Derive new secrets for the NEXT epoch
    old_init_secret = group.get("init_secret")
    commit_secret = bytes(32)

    joiner_secret = group["group_context"].extract_joiner_secret(old_init_secret, commit_secret)
    psk_secret = bytes(32)

    new_epoch_secret = group["group_context"].extract_epoch_secret(joiner_secret, psk_secret)
    new_init_secret = DeriveSecret(cs, new_epoch_secret, b"init")

    # 8. Create NEW GroupContext for the NEXT epoch
    new_group_context = GroupContext(
        cipher_suite=group["group_context"].cipher_suite,
        group_id=group["group_context"].group_id,
        epoch=group["epoch"] + 1,
        tree_hash=VLBytes(tree.hash(cs)),
        confirmed_transcript_hash=group["group_context"].confirmed_transcript_hash,
        extensions=group["group_context"].extensions
    )

    # 9. Prepare updated group state (NO WELCOME CREATED)
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

    print(f"   ✅ Tree updated for {new_member_id}")
    print(f"      New epoch: {updated_group['epoch']}, New leaf index: {new_leaf_index}")
    print(f"      Tree now has {len(tree.leaves)} leaves, {tree.nodes} nodes")

    return None, updated_group

def create_welcome_for_member(group, member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    """
    Create a Welcome message for a member using the FINAL tree state.
    This does NOT modify the tree - it only creates the Welcome.
    """
    print(f"\n=== Creating Welcome for {member_id} using final tree ===\n")

    # Ensure group_id_b64 exists
    if 'group_id_b64' not in group and 'group_id' in group:
        group_id_bytes = group['group_id'].data
        group['group_id_b64'] = base64.b64encode(group_id_bytes).decode('ascii')

    # 1. Fetch new member's KeyPackage
    new_kp_bytes = api_client.get_latest_keypackage(member_id)
    if not new_kp_bytes:
        print("Cannot create Welcome - KeyPackage not found")
        return None

    new_kp = KeyPackage.deserialize(bytearray(new_kp_bytes))
    new_leaf = new_kp.content.leaf_node

    # 2. Find the leaf index for this member in the FINAL tree
    # The member should already be in the tree from Loop 1
    target_leaf_index = None
    for i, leaf in enumerate(group["tree"].leaves):
        if isinstance(leaf, LeafNode):
            # Compare by encryption_key or credential
            if leaf.value.encryption_key == new_leaf.value.encryption_key:
                target_leaf_index = i
                break
    
    if target_leaf_index is None:
        print(f"⚠️ Member {member_id} not found in tree, using next available index")
        target_leaf_index = len(group["tree"].leaves) - 1

    print(f"   Member will be at leaf index: {target_leaf_index}")

    # 3. Create Add proposal
    add_proposal = Add(key_package=new_kp)

    # 4. Create Commit (with no path, since tree is already updated)
    commit = Commit(proposals=[add_proposal], path=None)

    # 5. Build FramedContent + AuthenticatedContent
    sender = Sender(sender_type=SenderType.member, leaf_index=committer_index)
    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"] - 1,  # Use previous epoch for the commit
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

    # 6. Sign the commit
    tbs = authenticated_content.FramedContentTBS(group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature_bytes = SignWithLabel(cs, sign_content, committer_priv_bytes)
    authenticated_content.auth.signature = VLBytes(signature_bytes)

    # 7. Derive joiner_secret for the new member (using current group state)
    old_init_secret = group.get("init_secret")
    commit_secret = bytes(32)

    joiner_secret = group["group_context"].extract_joiner_secret(old_init_secret, commit_secret)
    psk_secret = bytes(32)

    # 8. Create the ratchet_tree extension with the FINAL tree
    tree = group["tree"]
    
    # Ensure all leaf indices are correct before serializing
    for i in range(len(tree.leaves)):
        if isinstance(tree.leaves[i], LeafNode):
            tree.leaves[i]._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    ratchet_tree_extension = Extension(
        extension_type=ExtensionType.ratchet_tree,
        extension_data=VLBytes(tree.serialize())
    )

    # 9. Build GroupInfo with the FINAL tree
    confirmed_data = b"confirmation" + authenticated_content.serialize()
    confirmation_tag = hashlib.sha256(confirmed_data).digest()

    # Use the current epoch (the epoch after the member was added)
    current_epoch = group["epoch"]
    
    group_info = GroupInfo(
        group_context=group["group_context"],
        confirmation_tag=VLBytes(confirmation_tag),
        signer=committer_index,
        signature=VLBytes(b""),
        extensions=[ratchet_tree_extension]
    )

    # 10. Prepare GroupSecrets for the new member
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),
        psks=[],
        path_secret=None
    )
    group_secrets_bytes = group_secrets.serialize()

    # 11. HPKE encrypt GroupSecrets to new member's init key
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

    # 12. Encrypt GroupInfo using welcome_secret
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

    # 13. Build final Welcome
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

    print(f"✅ Welcome created successfully for {member_id}")
    print(f"   Current epoch: {current_epoch}")
    print(f"   Tree has {len(tree.leaves)} leaves, {tree.nodes} nodes")
    print(f"   Welcome size: {len(welcome_bytes)} bytes")

    return welcome_bytes