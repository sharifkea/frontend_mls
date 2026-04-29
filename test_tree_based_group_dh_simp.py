# test_tree_based_group_dh_v2.py
# Improved Tree-based Group Diffie-Hellman (ART-style)

import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.Crypto._derive_secrets import DeriveSecret
from mls_stuff.Enums import CipherSuite

import create_keypakage

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519


def generate_member(username: str):
    _, init_priv, _ = create_keypakage.GeneratKeyPackage(username)
    priv_key = X25519PrivateKey.from_private_bytes(init_priv)
    pub_key = priv_key.public_key()

    print(f"   {username}: pub={pub_key.public_bytes_raw()[:8].hex()}...")

    return {
        'username': username,
        'private_key': priv_key,
        'public_key': pub_key,
        'init_priv_bytes': init_priv,
    }


class Node:
    def __init__(self, member=None):
        self.member = member          # dict or None
        self.left = None
        self.right = None
        self.parent = None


class BinaryTree:
    def __init__(self):
        self.root = None

    def build(self, members):
        """Build a complete binary tree"""
        if not members:
            return

        # Create leaves
        leaves = [Node(m) for m in members]

        # Build tree bottom-up
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                parent = Node()
                parent.left = current_level[i]
                current_level[i].parent = parent

                if i + 1 < len(current_level):
                    parent.right = current_level[i + 1]
                    current_level[i + 1].parent = parent

                next_level.append(parent)
            current_level = next_level

        self.root = current_level[0]


def derive_group_key(member, root, cipher_suite):
    """Compute group key from member's perspective"""
    print(f"\n🔐 {member['username']} computing group key...")

    # Find own leaf
    def find_leaf(node):
        if not node:
            return None
        if node.member and node.member['username'] == member['username']:
            return node
        return find_leaf(node.left) or find_leaf(node.right)

    leaf = find_leaf(root)
    if not leaf:
        print("   Could not find own leaf!")
        return None

    current_secret = DeriveSecret(cipher_suite, member['init_priv_bytes'], b"leaf")
    current_node = leaf
    step = 0

    while current_node.parent:
        parent = current_node.parent
        sibling = parent.left if parent.right is current_node else parent.right

        if sibling and sibling.member:   # sibling is leaf
            sibling_pub = sibling.member['public_key']
            shared = member['private_key'].exchange(sibling_pub)
            current_secret = DeriveSecret(cipher_suite, shared, b"node")
            print(f"   Step {step}: DH sibling → {current_secret[:8].hex()}...")
        else:
            current_secret = DeriveSecret(cipher_suite, current_secret, b"node")
            print(f"   Step {step}: KDF only")

        current_node = parent
        step += 1

    print(f"   Final Group Key: {current_secret[:16].hex()}")
    return current_secret


def test_v2():
    print("="*110)
    print("🧪 Tree-based Group Diffie-Hellman v2 - Improved")
    print("="*110)

    users = ["alice", "bob", "charlie"]
    members = [generate_member(u) for u in users]

    tree = BinaryTree()
    tree.build(members)

    group_keys = {}
    for m in members:
        key = derive_group_key(m, tree.root, cs)
        group_keys[m['username']] = key

    print("\n" + "="*110)
    print("FINAL RESULTS")
    print("="*110)

    first = None
    same = True
    for name, key in group_keys.items():
        print(f"   {name:10}: {key[:16].hex() if key else 'None'}")
        if first is None:
            first = key
        elif key != first:
            same = False

    if same and first:
        print("\n✅ SUCCESS! All users derived the **same** group key!")
    else:
        print("\n❌ Still different. We can continue tuning.")

    return same


if __name__ == "__main__":
    test_v2()