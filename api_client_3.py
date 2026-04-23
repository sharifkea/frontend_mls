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

def build_tree_from_database(group_id_b64: str, token: str, existing_tree: RatchetTree = None) -> tuple[RatchetTree, int, dict]:
    """
    Build tree from database - ALWAYS builds from scratch for consistency.
    """
    print(f"\n🌲 Building tree from database for group {group_id_b64}")
    
    # Get members from database
    members_response = api_client.get_group_members(group_id_b64, token)
    if 'error' in members_response:
        raise ValueError(f"Failed to get members: {members_response['error']}")
    
    members = members_response.get('members', [])
    members.sort(key=lambda m: m['leaf_index'])
    
    print(f"   Found {len(members)} members in database")
    for m in members:
        print(f"      Leaf {m['leaf_index']}: {m['username']}")
    
    # ALWAYS BUILD FROM SCRATCH
    print(f"   Building tree from scratch for {len(members)} members")
    
    # Get creator's leaf node to initialize tree
    creator_id = members[0]['user_id']
    creator_kp_bytes = api_client.get_latest_keypackage(creator_id)
    if not creator_kp_bytes:
        raise ValueError("Creator key package not found")
    
    creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes))
    creator_leaf = creator_kp.content.leaf_node
    
    # Create empty group using the working method
    from api_client import create_empty_group
    temp_group = create_empty_group(creator_leaf, "temp")
    tree = temp_group['tree']
    
    print(f"   Created base tree with {len(tree.leaves)} leaves")
    
    # Add all members (excluding creator, already at leaf 0)
    for member in members[1:]:
        leaf_index = member.get('leaf_index')
        user_id = member.get('user_id')
        username = member.get('username')
        
        kp_bytes = api_client.get_latest_keypackage(user_id)
        if not kp_bytes:
            print(f"   ⚠️ No KeyPackage for {username}, skipping")
            continue
        
        key_package = KeyPackage.deserialize(bytearray(kp_bytes))
        leaf_node = key_package.content.leaf_node
        leaf_node._leaf_index = leaf_index
        
        # Ensure tree is large enough
        while len(tree.leaves) <= leaf_index:
            tree.extend()
            print(f"      Extended tree to {len(tree.leaves)} leaves")
        
        tree[leaf_index] = leaf_node
        print(f"   ✅ Added leaf {leaf_index}: {username}")
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Get current epoch
    group_details = api_client.get_group_details(group_id_b64, token)
    current_epoch = group_details.get('last_epoch', 0)
    
    print(f"   Final tree: {len(tree.leaves)} leaves, {tree.nodes} nodes")
    print(f"   Current epoch: {current_epoch}")
    
    return tree, current_epoch, members

def create_welcome_simple(group_id_b64: str, new_member_id: str, 
                          joiner_secret: bytes, token: str) -> bytes:
    """
    Create a simple Welcome message containing ONLY the joiner_secret.
    No tree in the Welcome - tree is built from database.
    """
    print(f"\n📨 Creating simple Welcome for {new_member_id}")
    
    # 1. Fetch new member's KeyPackage
    kp_bytes = api_client.get_latest_keypackage(new_member_id)
    if not kp_bytes:
        print("Cannot create Welcome - KeyPackage not found")
        return None
    
    new_kp = KeyPackage.deserialize(bytearray(kp_bytes))
    
    # 2. Prepare GroupSecrets with ONLY joiner_secret
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),
        psks=[],
        path_secret=None
    )
    group_secrets_bytes = group_secrets.serialize()
    
    # 3. HPKE encrypt to new member's init key
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
    
    # 4. Create minimal Welcome (no GroupInfo, no tree)
    welcome = Welcome(
        cipher_suite=cs,
        secrets=[encrypted_group_secrets],
        encrypted_group_info=VLBytes(b"")  # Empty - tree comes from DB
    )
    
    welcome_message = MLSMessage(
        wire_format=WireFormat.MLS_WELCOME,
        msg_content=welcome
    )
    welcome_bytes = welcome_message.serialize()
    
    print(f"   Welcome created: {len(welcome_bytes)} bytes")
    return welcome_bytes

def process_welcome_simple(welcome_b64: str, private_key: bytes) -> bytes:
    """
    Process a simple Welcome message to extract joiner_secret.
    """
    print(f"\n🔓 Processing simple Welcome")
    
    welcome_bytes = base64.b64decode(welcome_b64)
    welcome_bytearray = bytearray(welcome_bytes)
    
    mls_msg = MLSMessage.deserialize(welcome_bytearray)
    welcome = mls_msg.msg_content
    
    if not welcome.secrets:
        raise ValueError("No secrets in welcome")
    
    encrypted_secret = welcome.secrets[0]
    enc_gs = encrypted_secret.encrypted_group_secrets
    
    group_secrets_raw = simple_hpke_open(
        private_key,
        b"MLS 1.0 external init secret",
        bytes(enc_gs.kem_output.data),
        bytes(enc_gs.ciphertext.data)
    )
    
    group_secrets = GroupSecrets.deserialize(bytearray(group_secrets_raw))
    joiner_secret = group_secrets.joiner_secret.to_bytes()
    
    print(f"   Joiner secret extracted: {joiner_secret[:8].hex()}...")
    return joiner_secret

def add_member_to_tree(group, new_member_id: str, committer_priv_bytes: bytes,new_leaf_index: int, 
                       committer_index: int = 0) -> tuple[bytes, dict]:
    """
    Add a member to the tree and return the joiner_secret.
    Does NOT create a Welcome message.
    """
    print(f"\n➕ Adding {new_member_id} to tree")
    
    # Fetch new member's KeyPackage
    new_kp_bytes = api_client.get_latest_keypackage(new_member_id)
    if not new_kp_bytes:
        return None, group
    
    new_kp = KeyPackage.deserialize(bytearray(new_kp_bytes))
    new_leaf = new_kp.content.leaf_node
    
    # Create Add proposal and Commit
    add_proposal = Add(key_package=new_kp)
    commit = Commit(proposals=[add_proposal], path=None)
    
    # Build FramedContent
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
    
    # Sign
    tbs = authenticated_content.FramedContentTBS(group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature_bytes = SignWithLabel(cs, sign_content, committer_priv_bytes)
    authenticated_content.auth.signature = VLBytes(signature_bytes)
    
    # Add leaf to tree
    tree = group["tree"]
    #new_leaf_index = len(tree.leaves)
    
    while tree.nodes <= new_leaf_index:
        tree.extend()
    
    tree[new_leaf_index] = new_leaf
    tree[new_leaf_index]._leaf_index = new_leaf_index
    # Update indices
    for i in range(len(tree.leaves)):
        if isinstance(tree.leaves[i], LeafNode):
            tree.leaves[i]._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Derive joiner_secret
    old_init_secret = group.get("init_secret")
    commit_secret = bytes(32)
    
    joiner_secret = group["group_context"].extract_joiner_secret(old_init_secret, commit_secret)
    psk_secret = bytes(32)
    new_epoch_secret = group["group_context"].extract_epoch_secret(joiner_secret, psk_secret)
    new_init_secret = DeriveSecret(cs, new_epoch_secret, b"init")
    
    # Update group
    updated_group = {
        "group_id": group["group_id"],
        "group_id_b64": group.get("group_id_b64"),
        "epoch": group["epoch"] + 1,
        "tree": tree,
        "group_context": group["group_context"],
        "epoch_secret": new_epoch_secret,
        "init_secret": new_init_secret,
        "members": group["members"] + [new_member_id],
    }
    group.update(updated_group)
    print(f"   📝   After adding tree: {len(tree.leaves)} leaves, {tree.nodes} nodes")
    print(f"   Member added at leaf {new_leaf_index}, new epoch: {group['epoch']}")
    
    return joiner_secret, updated_group