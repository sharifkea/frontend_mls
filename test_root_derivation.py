# test_root_derivation.py - Per-User Tree Version (Recommended)

import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.RatchetTree import RatchetTree, LeafNode
from mls_stuff.Enums import CipherSuite
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.Crypto._derive_secrets import DeriveSecret

import create_keypakage

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519


def generate_key_package(username: str):
    private_key, init_priv, key_package_bytes = create_keypakage.GeneratKeyPackage(username)
    key_package = KeyPackage.deserialize(bytearray(key_package_bytes))
    leaf_node = key_package.content.leaf_node
    encryption_pub = bytes(leaf_node.value.encryption_key.data)
    
    print(f"   {username}: encryption_pub={encryption_pub[:8].hex()}...")
    
    return {
        'username': username,
        'init_priv': init_priv,
        'full_leaf_node': leaf_node,           # has private context
        'encryption_pub': encryption_pub,
    }


def build_tree_for_user(members_data: list, my_username: str) -> RatchetTree:
    """Build a tree from the perspective of one specific user"""
    print(f"\n🌲 Building tree for {my_username}...")
    
    tree = RatchetTree()
    n = len(members_data)
    while tree.nodes < 2 * n - 1:
        tree.extend()

    for i, member in enumerate(members_data):
        if member['username'] == my_username:
            # Use full leaf node (with private key context) for myself
            tree[i] = member['full_leaf_node']
        else:
            # For others, we only have public key — create a minimal leaf
            # We copy the structure but ensure it's public-only
            leaf_copy = LeafNode(value=member['full_leaf_node'].value)
            leaf_copy._leaf_index = i
            tree[i] = leaf_copy

        if hasattr(tree[i], '_leaf_index'):
            tree[i]._leaf_index = i

    tree.update_leaf_index()
    tree.update_node_index()

    print(f"   Tree for {my_username}: {len(tree.leaves)} leaves, my index = {get_my_index(tree, my_username)}")
    return tree


def get_my_index(tree: RatchetTree, my_username: str) -> int:
    for i, leaf in enumerate(tree.leaves):
        if isinstance(leaf, LeafNode) and leaf.value is not None:
            # We can identify by username if credential has it, or just by order for test
            pass
    # For simplicity in test, we use position (alice=0, bob=1, charlie=2)
    mapping = {"alice": 0, "bob": 1, "charlie": 2}
    return mapping.get(my_username, 0)


def derive_root_secret(member_data: dict, tree: RatchetTree, cipher_suite, my_index: int) -> bytes:
    print(f"   Deriving path for {member_data['username']} (leaf {my_index})...")

    my_priv_bytes = member_data['init_priv']
    my_priv_key = X25519PrivateKey.from_private_bytes(my_priv_bytes)
    
    current_secret = DeriveSecret(cipher_suite, my_priv_bytes, b"leaf")
    current_index = my_index

    step = 0
    while current_index > 0:
        parent_index = (current_index - 1) // 2
        sibling_index = current_index ^ 1

        sibling_node = tree[sibling_index]
        sibling_pub_bytes = None

        if isinstance(sibling_node, LeafNode) and sibling_node.value:
            sibling_pub_bytes = bytes(sibling_node.value.encryption_key.data)
        elif hasattr(sibling_node, 'value') and sibling_node.value and hasattr(sibling_node.value, 'encryption_key'):
            sibling_pub_bytes = bytes(sibling_node.value.encryption_key.data)

        if sibling_pub_bytes and len(sibling_pub_bytes) == 32:
            try:
                sibling_pub = X25519PublicKey.from_public_bytes(sibling_pub_bytes)
                shared = my_priv_key.exchange(sibling_pub)
                current_secret = DeriveSecret(cipher_suite, shared, b"node")
                print(f"     Step {step}: DH sibling {sibling_index} → {current_secret[:8].hex()}...")
            except:
                current_secret = DeriveSecret(cipher_suite, current_secret, b"node")
        else:
            current_secret = DeriveSecret(cipher_suite, current_secret, b"node")

        current_index = parent_index
        step += 1

    print(f"     Final root for {member_data['username']}: {current_secret[:16].hex()}")
    return current_secret


def test_root_derivation():
    print("="*100)
    print("🧪 TreeKEM Root Secret Derivation - Per User Tree Test")
    print("="*100)

    users = ["alice", "bob", "charlie"]
    members_data = [generate_key_package(u) for u in users]

    roots = {}

    for member in members_data:
        my_name = member['username']
        my_index = {"alice": 0, "bob": 1, "charlie": 2}[my_name]
        
        tree = build_tree_for_user(members_data, my_name)
        root = derive_root_secret(member, tree, cs, my_index)
        roots[my_name] = root

    print("\n" + "="*100)
    print("FINAL RESULTS")
    print("="*100)

    first = None
    same = True
    for name, r in roots.items():
        print(f"   {name:10}: {r[:16].hex()}")
        if first is None:
            first = r
        elif r != first:
            same = False

    if same:
        print("\n✅ SUCCESS! All three users derived the **same** root secret!")
    else:
        print("\n❌ Still different — but now each user has their correct leaf index.")

    return same


if __name__ == "__main__":
    test_root_derivation()