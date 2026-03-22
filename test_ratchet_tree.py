import cryptography, base64, requests, sys, secrets, hashlib, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryp_hpke import simple_hpke_seal, simple_hpke_open
from flask import session
from app import user_crypto_store

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.RatchetTree import RatchetTree, RatchetNode, LeafNode
# setup_1
def reconstruct_minimal_tree(my_leaf_index: int, member_count: int) -> RatchetTree:
    """
    Rebuild a minimal RatchetTree with correct size and your position.
    
    Args:
        my_leaf_index: Your leaf index from group_members
        member_count: Number of active members (from DB or group_details)
    
    Returns:
        RatchetTree with at least enough leaves for all members
    """
    tree = RatchetTree()
    
    # Step 1: Ensure root exists (required by your BinaryTree base class)
    tree.root = RatchetNode()
    
    # Step 2: Extend tree until it has enough leaves
    # MLS trees are power-of-2 sized internally, but we extend to cover max leaf
    required_leaves = max(member_count, my_leaf_index + 1)  # at least cover your index
    
    while len(tree.leaves) < required_leaves:
        tree.extend()
        print(f"  Extended tree → now {len(tree.leaves)} leaves")
    
    # Step 3: Optional — mark your own leaf as occupied (placeholder)
    # This is not cryptographically required yet, but good for debugging
    if my_leaf_index < len(tree.leaves):
        # Replace blank RatchetNode with a minimal LeafNode placeholder
        # (real encryption/signing keys will come from commits later)
        placeholder_leaf = RatchetNode()  # or create minimal LeafNode if needed
        tree[my_leaf_index] = placeholder_leaf
    
    print(f"Reconstructed minimal tree: {len(tree.leaves)} leaves, your index: {my_leaf_index}")
    return tree
#to call the function
tree = reconstruct_minimal_tree(
    my_leaf_index=my_leaf_index,
    member_count=member_count  # or len(members)
)

group_state['tree'] = tree

