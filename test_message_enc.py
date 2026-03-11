# test_message_enc.py
import base64
import sys
import secrets
import requests
from create_keypakage import GeneratKeyPackage
import base64
from test_db_api import (
    test_create_group_with_id, test_add_group_member, test_send_message,
    test_update_group_epoch, test_get_group_details, test_user_registration, 
    test_user_login, test_upload_keypackage, test_get_latest_keypackage
)
from encrypted_message_proper import test_encrypted_message

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, ProtocolVersion, ProposalType, SenderType, ContentType, WireFormat
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._proposal import Add
from mls_stuff.MLS._commit import Commit
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.MLS import MLSMessage, Sender, AuthenticatedContent, FramedContent, FramedContentAuthData, FramedContentTBS
from mls_stuff.Misc import VLBytes, SignContent
from mls_stuff.Crypto._crypt_with_label import SignWithLabel
from mls_stuff.Crypto import GroupSecrets, EncryptedGroupSecrets, HPKECiphertext
from mls_stuff.Objects import GroupContext
from mls_stuff.Crypto._derive_secrets import DeriveSecret

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
BASE_URL = "http://localhost:8000"

def create_empty_group(creator_leaf_node: LeafNode, creator_name: str = "bob"):
    print(f"\n=== {creator_name.capitalize()} creates empty group ===")

    # 1. Random group ID (public)
    group_id_bytes = secrets.token_bytes(16)
    group_id = VLBytes(group_id_bytes)
    print("Group ID (hex):", group_id_bytes.hex())

    # 2. Initialize tree
    tree = RatchetTree()
    # Extend until at least one leaf slot exists
    while tree.root is None or len(tree.leaves) < 1:
        tree.extend()

    # Assign creator at leaf index 0
    tree[0] = creator_leaf_node

    # IMPORTANT: update indices NOW, before any hash or serialize
    tree.update_node_index()
    tree.update_leaf_index()

    # Debug: check if index was set
    print(f"Leaf 0 index after update: {tree[0]._leaf_index}")  # should be 0

    # 3. Generate the INITIAL EPOCH SECRET (32 bytes for AES-256)
    epoch_secret = secrets.token_bytes(32)  #  THIS IS THE EPOCH SECRET!
    print(f"Initial epoch secret (first 16 bytes): {epoch_secret[:16].hex()}...")
    
    # 4. Generate init secret for next epoch
    init_secret = DeriveSecret(cs, epoch_secret, b"init")
    print(f"Init secret (first 16 bytes): {init_secret[:16].hex()}...")

    # 5. Group context (epoch 0)
    tree_hash = VLBytes(tree.hash(cs))
    confirmed_hash = VLBytes(b"")

    group_context = GroupContext(
        cipher_suite=cs,
        group_id=group_id,
        epoch=0,
        tree_hash=tree_hash,
        confirmed_transcript_hash=confirmed_hash,
        extensions=[]   # empty list of extensions
    )

    print("Empty group created successfully!")
    print(f"  Epoch: 0")
    print(f"  Members: ['{creator_name}']")
    print(f"  Tree hash (prefix): {tree_hash.data.hex()[:32]}...")

    return {
        "group_id": group_id,                    # VLBytes object
        "group_id_b64": base64.b64encode(group_id_bytes).decode('ascii'), 
        "epoch": 0,
        "tree": tree,
        "group_context": group_context,
        "members": [creator_name],
        "epoch_secret": epoch_secret,
        "init_secret": init_secret
    }
   

def fetch_keypackage(user_id: str) -> bytes | None:
    url = f"{BASE_URL}/key_packages/{user_id}/latest"
    r = requests.get(url)
    if r.status_code == 200:
        print(f"Fetched {user_id}: {len(r.content)} bytes")
        return r.content
    print(f"Fetch {user_id} failed: {r.status_code} {r.text}")
    return None

def add_member(group, new_member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    print(f"\n=== Adding {new_member_id} to group ===\n")

    if 'group_id_b64' not in group and 'group_id' in group:
        group_id_bytes = group['group_id'].data
        group['group_id_b64'] = base64.b64encode(group_id_bytes).decode('ascii')

    # 1. Fetch new member's KeyPackage
    new_kp_bytes = test_get_latest_keypackage(new_member_id)
    if not new_kp_bytes:
        print("Cannot add - KeyPackage not found")
        return None

    new_kp_bytes_mutable = bytearray(new_kp_bytes)
    new_kp = KeyPackage.deserialize(new_kp_bytes_mutable)
    new_leaf = new_kp.content.leaf_node

    # 2. Create Add proposal
    add_proposal = Add(key_package=new_kp)

    # 3. Create Commit
    commit = Commit(
        proposals=[add_proposal],
        path=None  # no path update for simple add
    )

    # 4. Create FramedContent
    sender = Sender(sender_type=SenderType.member, leaf_index=committer_index)

    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.commit,
        commit=commit
    )

    # 5. Create FramedContentAuthData
    auth = FramedContentAuthData(signature=VLBytes(b""), confirmation_tag=None)

    # 6. Create AuthenticatedContent
    authenticated_content = AuthenticatedContent(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        content=framed_content,
        auth=auth
    )

    # 7. Sign the content
    tbs = authenticated_content.FramedContentTBS(group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature_bytes = SignWithLabel(cs, sign_content, committer_priv_bytes)
    authenticated_content.auth.signature = VLBytes(signature_bytes)

    # 8. Create MLSMessage (PublicMessage)
    public_commit = MLSMessage(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        msg_content=authenticated_content
    )

    print("PublicMessage (Commit) created and signed - size:", len(public_commit.serialize()))

    # 9. Apply Commit to tree (add new leaf)
    tree = group["tree"]
    new_leaf_index = len(tree.leaves)  # next free index

    # Extend tree if necessary
    while tree.nodes <= new_leaf_index * 2:
        tree.extend()

    # Assign new leaf
    tree[new_leaf_index] = new_leaf

    # Manual fix: set _leaf_index on the new leaf
    tree[new_leaf_index]._leaf_index = new_leaf_index

    # Update indices (for other nodes)
    tree.update_node_index()
    tree.update_leaf_index()

    print(f"New leaf index after manual set: {tree[new_leaf_index]._leaf_index}")
    
    # Get current secrets
    old_epoch_secret = group.get("epoch_secret")
    old_init_secret = group.get("init_secret")
    
    if old_epoch_secret is None or old_init_secret is None:
        print(" ERROR: No epoch/init secret found in group!")
        return None
    
    print(f"Old epoch secret (first 16): {old_epoch_secret[:16].hex()}...")
    
    # For a simple add with no path, commit_secret is zeros
    commit_secret = bytes(32)  # 32 bytes of zeros
    
    # Calculate joiner_secret using GroupContext method
    joiner_secret = group["group_context"].extract_joiner_secret(old_init_secret, commit_secret)
    print(f"Joiner secret (first 16): {joiner_secret[:16].hex()}...")
    
    # PSK secret is zeros for now
    psk_secret = bytes(32)
    
    # Calculate new epoch secret
    new_epoch_secret = group["group_context"].extract_epoch_secret(joiner_secret, psk_secret)
    print(f"New epoch secret (first 16): {new_epoch_secret[:16].hex()}...")
    
    # Calculate new init secret
    new_init_secret = DeriveSecret(cs, new_epoch_secret, b"init")
    
    # Update group with new secrets
    group["epoch_secret"] = new_epoch_secret
    group["init_secret"] = new_init_secret
    
    # 11. Update epoch & context
    group["epoch"] += 1
    group["group_context"].epoch = group["epoch"]
    group["group_context"].tree_hash = VLBytes(tree.hash(cs))
    group["members"].append(new_member_id)

    # 12. Generate Welcome (simplified)
    joiner_secret = secrets.token_bytes(32)  # In real MLS, this is derived
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),
        psks=[],
        path_secret=None
    )

    dummy_hpke = HPKECiphertext(
        kem_output=VLBytes(secrets.token_bytes(32)),
        ciphertext=VLBytes(group_secrets.serialize())
    )

    encrypted_secrets = EncryptedGroupSecrets(
        new_member=VLBytes(b"dummy_ref"),
        encrypted_group_secrets=dummy_hpke
    )

    welcome = Welcome(
        cipher_suite=cs,
        secrets=[encrypted_secrets],
        encrypted_group_info=VLBytes(b"")
    )

    print(f" {new_member_id} added!")
    print(f"  New epoch: {group['epoch']}")
    print(f"  Members: {group['members']}")
    print(f"  New epoch secret saved")

    return welcome

if __name__ == "__main__":

    test_user = "alice"
    user_id_alice = test_user_registration(test_user,"1234")
    if user_id_alice:
        user_id_alice, token_alice = test_user_login(test_user,"1234")
        if user_id_alice and token_alice:
            alice_priv_bytes, kp_user_alice=GeneratKeyPackage(test_user)
            ref_hash_alice, key_package_id_alice = test_upload_keypackage(user_id_alice, kp_user_alice)
    
    test_user = "bob"
    user_id_bob = test_user_registration(test_user,"1234")
    if user_id_bob:
        user_id_bob, token_bob = test_user_login(test_user,"1234")
        if user_id_bob and token_bob:
            bob_priv_bytes, kp_user_bob=GeneratKeyPackage(test_user)
            ref_hash_bob, key_package_id_bob = test_upload_keypackage(user_id_bob, kp_user_bob)
    
    bob_latest_kp = test_get_latest_keypackage(user_id_bob)
    if not bob_latest_kp:
        print("Cannot continue — Bob not found")
        sys.exit(1)

    bob_kp_bytes_mutable = bytearray(bob_latest_kp)
    bob_kp = KeyPackage.deserialize(bob_kp_bytes_mutable)
    bob_leaf = bob_kp.content.leaf_node
    print("Bob's LeafNode extracted")

    group = create_empty_group(bob_leaf, "bob")
    
    welcome = add_member(group, user_id_alice, bob_priv_bytes)
    
    if welcome:
        print("Welcome ready to send to Alice!")
        
        # Test encrypted messages
        test_encrypted_message(
            group, 
            alice_index=1,  # Alice is leaf index 1
            bob_index=0,    # Bob is leaf index 0
            epoch_secret=group["epoch_secret"]  # The epoch secret we've been tracking
        )
        
  

