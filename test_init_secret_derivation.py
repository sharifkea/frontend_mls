# test_init_secret_derivation.py
import sys
import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.RatchetTree import RatchetTree, LeafNode
from mls_stuff.Enums import CipherSuite
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.Crypto._derive_secrets import DeriveSecret
from mls_stuff.Objects import GroupContext
from mls_stuff.Misc import VLBytes

import create_keypakage

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519


def generate_key_package(username: str):
    """Generate key package for a user"""
    private_key, init_priv, key_package_bytes = create_keypakage.GeneratKeyPackage(username)
    key_package = KeyPackage.deserialize(bytearray(key_package_bytes))
    leaf_node = key_package.content.leaf_node
    encryption_pub = bytes(leaf_node.value.encryption_key.data)
    
    print(f"   {username}: encryption_pub={encryption_pub[:8].hex()}...")
    
    return {
        'username': username,
        'private_key': private_key,
        'init_priv': init_priv,
        'full_leaf_node': leaf_node,
        'encryption_pub': encryption_pub,
    }


def create_group_with_init_secret(creator_data: dict) -> dict:
    """
    Simulate group creation with random init_secret
    This is what MLS actually does
    """
    print(f"\n🏗️ Creating group with {creator_data['username']}...")
    
    # 1. Create empty tree
    tree = RatchetTree()
    while tree.root is None or len(tree.leaves) < 1:
        tree.extend()
    
    # 2. Add creator at leaf 0
    tree[0] = creator_data['full_leaf_node']
    tree[0]._leaf_index = 0
    tree.update_leaf_index()
    tree.update_node_index()
    
    # 3. Generate RANDOM init_secret (MLS way - never from tree hash!)
    init_secret = secrets.token_bytes(32)
    print(f"   Generated init_secret: {init_secret[:16].hex()}...")
    
    # 4. Derive epoch_secret from init_secret
    epoch_secret = DeriveSecret(cs, init_secret, b"epoch")
    print(f"   Derived epoch_secret: {epoch_secret[:16].hex()}...")
    
    # 5. Create group context
    tree_hash = VLBytes(tree.hash(cs))
    group_context = GroupContext(
        cipher_suite=cs,
        group_id=VLBytes(secrets.token_bytes(16)),
        epoch=0,
        tree_hash=tree_hash,
        confirmed_transcript_hash=VLBytes(b""),
        extensions=[]
    )
    
    return {
        'tree': tree,
        'group_context': group_context,
        'init_secret': init_secret,
        'epoch_secret': epoch_secret,
        'members': [creator_data['username']],
        'creator': creator_data['username']
    }


def joiner_derives_epoch_secret(joiner_data: dict, group_state: dict, joiner_secret: bytes) -> dict:
    """
    Simulate a member joining and deriving epoch_secret from joiner_secret
    """
    print(f"\n🔐 {joiner_data['username']} joining group...")
    
    # 1. Joiner receives joiner_secret via Welcome (HPKE encrypted in real world)
    print(f"   Received joiner_secret: {joiner_secret[:16].hex()}...")
    
    # 2. Derive init_secret from joiner_secret (MLS way)
    init_secret = DeriveSecret(cs, joiner_secret, b"init")
    print(f"   Derived init_secret: {init_secret[:16].hex()}...")
    
    # 3. Derive epoch_secret from init_secret
    epoch_secret = DeriveSecret(cs, init_secret, b"epoch")
    print(f"   Derived epoch_secret: {epoch_secret[:16].hex()}...")
    
    # 4. Verify it matches the group's epoch_secret
    matches = epoch_secret == group_state['epoch_secret']
    print(f"   Matches group epoch_secret: {'✅ YES' if matches else '❌ NO'}")
    
    # 5. Build tree structure (for member list, NOT for key derivation!)
    # Add joiner's leaf to the tree
    tree = group_state['tree']
    new_leaf_index = len(tree.leaves)
    
    while tree.nodes <= new_leaf_index * 2:
        tree.extend()
    
    tree[new_leaf_index] = joiner_data['full_leaf_node']
    tree[new_leaf_index]._leaf_index = new_leaf_index
    
    for i in range(len(tree.leaves)):
        if isinstance(tree.leaves[i], LeafNode):
            tree.leaves[i]._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    return {
        'tree': tree,
        'init_secret': init_secret,
        'epoch_secret': epoch_secret,
        'leaf_index': new_leaf_index,
        'matches': matches
    }


def creator_adds_member(creator_data, group_state, new_member_data):
    # ❌ WRONG - random joiner_secret
    # joiner_secret = secrets.token_bytes(32)
    
    # ✅ CORRECT - derive joiner_secret from current epoch_secret
    current_epoch_secret = group_state['epoch_secret']
    joiner_secret = DeriveSecret(cs, current_epoch_secret, b"joiner")
    
    # Now joiner_secret is deterministic based on epoch_secret
    # New member will derive the SAME epoch_secret back!
    #print(f"   New epoch_secret: {new_epoch_secret[:16].hex()}...")
    return joiner_secret, group_state
    
    
    
    


def test_init_secret_derivation():
    """Test that all members can derive the same epoch_secret using init_secret"""
    print("=" * 80)
    print("🧪 MLS init_secret-based Root Derivation Test")
    print("=" * 80)
    
    # Step 1: Generate key packages for 3 users
    print("\n📦 Generating key packages...")
    users = ["alice", "bob", "charlie"]
    members_data = {}
    
    for username in users:
        members_data[username] = generate_key_package(username)
    
    # Step 2: Alice creates group with random init_secret
    group_state = create_group_with_init_secret(members_data["alice"])
    print(f"\n📊 Group created with epoch_secret: {group_state['epoch_secret'][:16].hex()}...")
    
    # Step 3: Bob joins - receives joiner_secret from Alice
    print("\n" + "=" * 80)
    print("🔄 FIRST JOIN: Bob joins the group")
    print("=" * 80)
    
    # Alice generates joiner_secret for Bob
    joiner_secret_bob, group_state = creator_adds_member(
        members_data["alice"], group_state, members_data["bob"]
    )
    
    # Bob receives and processes Welcome
    bob_result = joiner_derives_epoch_secret(members_data["bob"], group_state, joiner_secret_bob)
    
    # Step 4: Charlie joins
    print("\n" + "=" * 80)
    print("🔄 SECOND JOIN: Charlie joins the group")
    print("=" * 80)
    
    joiner_secret_charlie, group_state = creator_adds_member(
        members_data["alice"], group_state, members_data["charlie"]
    )
    
    charlie_result = joiner_derives_epoch_secret(members_data["charlie"], group_state, joiner_secret_charlie)
    
    # Step 5: Verify all members have the SAME epoch_secret
    print("\n" + "=" * 80)
    print("📊 FINAL VERIFICATION")
    print("=" * 80)
    
    all_epoch_secrets = {
        "alice": group_state['epoch_secret'],
        "bob": bob_result['epoch_secret'],
        "charlie": charlie_result['epoch_secret']
    }
    
    first_secret = None
    all_match = True
    for name, secret in all_epoch_secrets.items():
        print(f"   {name}: {secret[:16].hex()}...")
        if first_secret is None:
            first_secret = secret
        elif secret != first_secret:
            all_match = False
            print(f"      ❌ MISMATCH for {name}!")
    
    print("\n" + "=" * 80)
    if all_match:
        print("✅ SUCCESS! All members derived the SAME epoch_secret!")
        print(f"   Shared epoch_secret: {first_secret[:32].hex()}")
        print("\n🔐 Security property: epoch_secret derived from init_secret/joiner_secret")
        print("   NOT from tree hash! DB compromise cannot reveal this secret.")
    else:
        print("❌ FAILURE: Members derived different epoch_secrets")
    
    print("\n" + "=" * 80)
    
    # Additional security check
    print("\n🔒 SECURITY VERIFICATION:")
    print("   tree.hash():", group_state['tree'].hash(cs)[:16].hex())
    print("   epoch_secret:", first_secret[:16].hex() if first_secret else "None")
    print("   Are they different?", "✅ YES" if first_secret and group_state['tree'].hash(cs)[:16].hex() != first_secret[:16].hex() else "⚠️ WARNING")
    
    return all_match


def test_vulnerable_tree_hash_approach():
    """Demonstrate why tree.hash() approach is vulnerable"""
    print("\n" + "=" * 80)
    print("⚠️ DEMONSTRATION: Vulnerable tree.hash() approach")
    print("=" * 80)
    
    # Generate key packages
    members_data = {}
    for username in ["alice", "bob", "charlie"]:
        members_data[username] = generate_key_package(username)
    
    # Build tree (public data)
    tree = RatchetTree()
    while tree.nodes < 5:  # Enough for 3 leaves
        tree.extend()
    
    for i, username in enumerate(["alice", "bob", "charlie"]):
        tree[i] = members_data[username]['full_leaf_node']
        tree[i]._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Attacker with DB access can compute this!
    root_secret = tree.hash(cs)
    vulnerable_epoch = DeriveSecret(cs, root_secret, b"epoch")
    
    print(f"\n   tree.hash(): {root_secret[:16].hex()}...")
    print(f"   Derived epoch (VULNERABLE): {vulnerable_epoch[:16].hex()}...")
    print("\n   ⚠️ ANYONE with database access can compute this!")
    print("   ❌ This is why tree.hash() should NOT be used for key derivation.\n")


if __name__ == "__main__":
    print("🔬" * 20)
    print("MLS INIT_SECRET DERIVATION TESTS")
    print("🔬" * 20)
    
    # Show the vulnerable approach
    test_vulnerable_tree_hash_approach()
    
    # Test the secure approach
    success = test_init_secret_derivation()
    
    print("\n" + "=" * 80)
    print("FINAL RECOMMENDATION")
    print("=" * 80)
    if success:
        print("✅ Use init_secret/joiner_secret for epoch secret derivation.")
        print("❌ Remove all calls to derive_epoch_secret_from_tree().")
        print("✅ Store epoch_secret only in memory (user_crypto_store).")
        print("✅ Never store epoch_secret in database.")
    else:
        print("⚠️ Test failed - need to debug implementation.")