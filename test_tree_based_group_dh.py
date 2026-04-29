# test_tree_based_group_dh.py
# Tree-based Group Diffie-Hellman (ART-style) Test

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
    """Generate key package and return necessary data"""
    private_key, init_priv, key_package_bytes = create_keypakage.GeneratKeyPackage(username)
    key_package = KeyPackage.deserialize(bytearray(key_package_bytes))
    leaf_node = key_package.content.leaf_node
    encryption_pub = bytes(leaf_node.value.encryption_key.data)

    print(f"   {username}: pub={encryption_pub[:8].hex()}...")

    return {
        'username': username,
        'init_priv': init_priv,           # X25519 private key (32 bytes)
        'full_leaf': leaf_node,
        'encryption_pub': encryption_pub,
    }


def build_public_tree(members_data: list) -> RatchetTree:
    """Build the public ratchet tree (same for everyone)"""
    print("\n🌲 Building public ratchet tree...")
    tree = RatchetTree()
    n = len(members_data)

    # Extend tree to have enough nodes
    while tree.nodes < 2 * n - 1:
        tree.extend()

    # Insert public leaf nodes
    for i, member in enumerate(members_data):
        # Create a public-only copy of the leaf
        leaf_copy = LeafNode(value=member['full_leaf'].value)
        leaf_copy._leaf_index = i
        tree[i] = leaf_copy

    tree.update_leaf_index()
    tree.update_node_index()

    print(f"   Public tree built: {len(tree.leaves)} leaves, {tree.nodes} nodes")
    print(f"   tree.hash(cs) = {tree.hash(cs)[:16].hex()}...")
    return tree


def derive_group_key_tree_dh(member_data: dict, public_tree: RatchetTree, cipher_suite, my_index: int) -> bytes:
    """Tree-based Group Diffie-Hellman derivation (ART-style)"""
    print(f"\n🔐 Computing Group Key for {member_data['username']} (leaf {my_index})...")

    my_priv_bytes = member_data['init_priv']
    my_priv_key = X25519PrivateKey.from_private_bytes(my_priv_bytes)

    # Start at leaf with our own private key material
    current_secret = DeriveSecret(cipher_suite, my_priv_bytes, b"leaf")

    current_index = my_index

    while current_index > 0:
        parent_index = (current_index - 1) // 2
        sibling_index = current_index ^ 1   # sibling = flip last bit

        sibling_node = public_tree[sibling_index]

        # Extract sibling's public encryption key
        sibling_pub_bytes = None
        if isinstance(sibling_node, LeafNode) and sibling_node.value:
            sibling_pub_bytes = bytes(sibling_node.value.encryption_key.data)
        elif hasattr(sibling_node, 'value') and sibling_node.value and hasattr(sibling_node.value, 'encryption_key'):
            sibling_pub_bytes = bytes(sibling_node.value.encryption_key.data)

        if sibling_pub_bytes and len(sibling_pub_bytes) == 32:
            try:
                sibling_pub_key = X25519PublicKey.from_public_bytes(sibling_pub_bytes)
                shared_secret = my_priv_key.exchange(sibling_pub_key)
                # KDF the shared secret to get parent secret
                current_secret = DeriveSecret(cipher_suite, shared_secret, b"node")
                print(f"   Step: DH with sibling {sibling_index} → parent {parent_index} | {current_secret[:8].hex()}...")
            except Exception as e:
                print(f"   DH failed at sibling {sibling_index}, falling back to KDF")
                current_secret = DeriveSecret(cipher_suite, current_secret, b"node")
        else:
            current_secret = DeriveSecret(cipher_suite, current_secret, b"node")
            print(f"   No sibling key at {sibling_index}, using KDF")

        current_index = parent_index

    print(f"   Final Group Key for {member_data['username']}: {current_secret[:16].hex()}")
    return current_secret


def test_tree_based_group_dh():
    print("=" * 100)
    print("🧪 Tree-based Group Diffie-Hellman (ART-style) Test")
    print("=" * 100)

    users = ["alice", "bob", "charlie"]
    members_data = [generate_key_package(u) for u in users]

    # Build one public tree (shared view)
    public_tree = build_public_tree(members_data)

    # Each user computes the group key independently
    group_keys = {}

    for member in members_data:
        my_name = member['username']
        my_index = {"alice": 0, "bob": 1, "charlie": 2}[my_name]

        key = derive_group_key_tree_dh(member, public_tree, cs, my_index)
        group_keys[my_name] = key

    print("\n" + "=" * 100)
    print("FINAL RESULTS")
    print("=" * 100)

    first_key = None
    all_same = True
    for name, key in group_keys.items():
        print(f"   {name:10}: {key[:16].hex()}")
        if first_key is None:
            first_key = key
        elif key != first_key:
            all_same = False

    if all_same:
        print("\n✅ SUCCESS! All users derived the **same** group key using Tree-based Group DH!")
        print(f"   Group Key = {first_key[:32].hex()}")
    else:
        print("\n❌ Different group keys — we can still tune the KDF labels.")

    return all_same


if __name__ == "__main__":
    test_tree_based_group_dh()