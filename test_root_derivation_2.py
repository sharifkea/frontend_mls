# test_tgdh_root_key.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from model.binary_key_tree import BinaryKeyTree
import hashlib

from mls_stuff.mls_stuff.Enums import CipherSuite
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

def test_tgdh_root_derivation():
    print("=" * 70)
    print("🧪 TGDH Root Secret Derivation Test")
    print("=" * 70)
    
    # Step 1: Create DH parameters
    print("\n📦 Generating DH parameters...")
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    
    # Step 2: Create tree and add members one by one
    print("\n👥 Creating group with Alice, Bob, Charlie...")
    tree = BinaryKeyTree()
    
    # Add Alice
    print("   Adding Alice...")
    tree.add_member("Alice", parameters)
    
    # Add Bob
    print("   Adding Bob...")
    tree.add_member("Bob", parameters)
    
    # Add Charlie
    print("   Adding Charlie...")
    tree.add_member("Charlie", parameters)
    
    # Refresh keys to compute shared secrets up the tree
    print("\n🔄 Refreshing tree keys...")
    tree.refresh_keys(parameters, force=True)
    
    # Step 3: Get the group key from the root
    group_key = tree.get_group_key()
    print(f"\n🔑 Root group key: {group_key[:32].hex() if group_key else 'None'}...")
    
    # Refresh keys to compute shared secrets up the tree
    print("\n🔄 Refreshing tree keys...")
    tree.refresh_keys(parameters, force=True)
    
    # Step 3: Get the group key from the root
    group_key = tree.get_group_key()
    print(f"\n🔑 Root group key: {group_key[:32].hex() if group_key else 'None'}...")

    # Step 4: Derive epoch secret from root key
    if group_key:
        epoch_secret = hashlib.sha256(group_key + b"epoch").digest()
        print(f"🔐 Epoch secret: {epoch_secret[:32].hex()}...")
    
    # Step 5: Verify each member can compute the same key
    print("\n🔍 Verifying each member can compute the same key...")
    
    member_keys = {}
    
    # Get all leaves using iter_leaves()
    leaves = list(tree.iter_leaves())
    
    for i, leaf in enumerate(leaves):
        member_name = tree.members[i] if i < len(tree.members) else f"Member_{i}"
        
        # Walk up from leaf to root to get the shared key
        current_node = leaf
        current_shared = leaf.shared_key
        
        while current_node.parent:
            current_node = current_node.parent
            if current_node.shared_key:
                current_shared = current_node.shared_key
        
        if current_shared:
            derived_epoch = hashlib.sha256(current_shared + b"epoch").digest()
            member_keys[member_name] = derived_epoch
            print(f"   {member_name}: {derived_epoch[:16].hex()}...")
        else:
            print(f"   {member_name}: No shared key found")
    
    # Step 6: Check consistency
    unique_keys = set([str(k) for k in member_keys.values() if k])
    print(f"\n📊 Unique epoch secrets found: {len(unique_keys)}")
    
    if len(unique_keys) == 1:
        print("\n✅ SUCCESS! All members derive the SAME epoch secret!")
        return parameters, True, tree
    else:
        print("\n❌ FAILURE: Members derived different secrets")
        return False


def test_tgdh_add_member(parameters):
    """Test root key derivation when adding members"""
    print("\n" + "=" * 70)
    print("🧪 TGDH Add Member Test")
    print("=" * 70)
    
    #parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    
    # Create tree with Alice only
    print("\n👥 Creating group with Alice...")
    tree = BinaryKeyTree()
    tree.add_member("Alice", parameters)
    tree.refresh_keys(parameters, force=True)
    
    group_key = tree.get_group_key()
    print(f"   Root key after creation: {group_key[:16].hex() if group_key else 'None'}...")
    
    # Add Bob
    print("\n➕ Adding Bob...")
    tree.add_member("Bob", parameters)
    tree.refresh_keys(parameters, force=True)
    group_key = tree.get_group_key()
    print(f"   Root key after adding Bob: {group_key[:16].hex() if group_key else 'None'}...")
    
    # Add Charlie
    print("\n➕ Adding Charlie...")
    tree.add_member("Charlie", parameters)
    tree.refresh_keys(parameters, force=True)
    group_key = tree.get_group_key()
    print(f"   Root key after adding Charlie: {group_key[:16].hex() if group_key else 'None'}...")
    
    # Verify all members derive same key
    print("\n🔍 Verifying all members derive same key...")
    derived_keys = {}
    
    leaves = list(tree.iter_leaves())
    for i, leaf in enumerate(leaves):
        member_name = tree.members[i] if i < len(tree.members) else f"Member_{i}"
        
        current_node = leaf
        current_shared = leaf.shared_key
        
        while current_node.parent:
            current_node = current_node.parent
            if current_node.shared_key:
                current_shared = current_node.shared_key
        
        if current_shared:
            epoch = hashlib.sha256(current_shared + b"epoch").digest()
            derived_keys[member_name] = epoch
            print(f"   {member_name}: {epoch[:16].hex()}...")
    
    unique_keys = set([str(k) for k in derived_keys.values() if k])
    
    if len(unique_keys) == 1:
        print("\n✅ SUCCESS! All members derive the SAME epoch secret!")
        return True
    else:
        print("\n❌ FAILURE: Different secrets detected")
        return False


if __name__ == "__main__":
    print("\n" + "🔬" * 35)
    print("TGDH ROOT SECRET DERIVATION TESTS")
    print("🔬" * 35)
    
    parameters,test1 = test_tgdh_root_derivation()
    test2 = test_tgdh_add_member(parameters)
    
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"   Root derivation test: {'✅ PASSED' if test1 else '❌ FAILED'}")
    print(f"   Add member test:      {'✅ PASSED' if test2 else '❌ FAILED'}")