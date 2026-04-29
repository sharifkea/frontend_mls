import hashlib
import base64
import json

from .tree_node import TreeNode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


class BinaryKeyTree:
    """
    Represents a full binary key tree used in Tree-based Group Diffie-Hellman (TGDH).
    Supports member joins, key refresh, serialization, and deterministic synthetic key generation.
    """

    def __init__(self):
        self.root: TreeNode = None
        self.members: list[str] = []

    def add_member(self, member_name, parameters: dh.DHParameters = None, public_key=None):
        """Add a new member to the tree and attach their public key if provided."""
        new_leaf = TreeNode(is_leaf=True)
        new_leaf.member = member_name

        if public_key is not None:
            new_leaf.public_key = public_key
            new_leaf.private_key = None  # Important: prevent accidental use
        elif parameters is not None:
            new_leaf.generate_keys(parameters)
        else:
            print(f"[ERROR] Cannot add member {member_name}: no keys provided.")
            return

        self.members.append(member_name)

        if not self.root:
            self.root = new_leaf
        else:
            self.root = self._merge_trees(self.root, new_leaf)

    def find_leaf_by_member(self, member_name):
        """Find and return the leaf node for a given member name."""
        def recurse(node):
            if node is None:
                return None
            if node.is_leaf and node.member == member_name:
                return node
            return recurse(node.left) or recurse(node.right)
        return recurse(self.root)


    def _merge_trees(self, left: TreeNode, right: TreeNode) -> TreeNode:
        """Merge two subtrees under a new parent node."""
        parent = TreeNode()
        parent.left = left
        parent.right = right
        left.parent = parent
        right.parent = parent
        return parent

    def refresh_keys(self, parameters: dh.DHParameters, force=False):
        """
        Recursively recompute shared and public keys from leaves to root.
        Nodes flagged with _skip_refresh or frozen_public_key are skipped unless force=True.
        """
        def recurse(node: TreeNode):
            if node is None:
                return

            recurse(node.left)
            recurse(node.right)

            if node.public_key and node.shared_key and node.private_key is None and not force:
                # Skip recomputation — assume sponsor attached synthetic blinded key
                return

            if node.is_leaf:
                return

            if (node._skip_refresh or node.frozen_public_key) and not force:
                return

            # Check children public keys
            if not node.left or not node.right:
                print("[ERROR] Cannot refresh keys: missing child node.")
                return

            # Skip if no way to compute shared key
            if (
                not node.left or not node.right or
                not ((node.left.private_key and node.right.public_key) or
                    (node.right.private_key and node.left.public_key))
            ):
                print("[DEBUG] Skipping refresh at node: no private/public key pair in children.")
                return

            node.compute_shared_key()


        recurse(self.root)

    def get_group_key(self, mode: str = "no_fs", context: dict = None) -> bytes:
        if not self.root or not self.root.shared_key:
            return None

        base_key = self.root.shared_key

        if mode == "no_fs":
            return base_key[:32]  # return raw 32 bytes

        elif mode == "fs":
            if not context:
                context = {}
            context_str = json.dumps(context, sort_keys=True)
            context_bytes = context_str.encode()
            derived = hashlib.sha256(base_key + context_bytes).digest()
            return derived[:32]  # raw 32 bytes

        elif mode == "fs_pcs":
            if not context:
                context = {}
            context_str = json.dumps(context, sort_keys=True)
            context_bytes = context_str.encode()
            derived = hashlib.sha512(base_key + context_bytes).digest()
            return derived[:32]  # raw 32 bytes

        return None

    def serialize(self) -> dict:
        """Serialize the entire tree (structure and public keys) to a dictionary."""
        def walk(node):
            if node is None:
                return None

            data = {
                "is_leaf": node.is_leaf,
                "member": node.member,
                "public_key": node.serialize_public_key(),
                "frozen_public_key": base64.b64encode(node.frozen_public_key).decode() if node.frozen_public_key else None,
                "has_blinded_key": node._has_blinded_key,
            }

            if node.left:
                data["left"] = walk(node.left)
            if node.right:
                data["right"] = walk(node.right)

            return data

        return {"root": walk(self.root), "members": self.members}

    @classmethod
    def deserialize(cls, tree_data: dict, local_member: str, parameters: dh.DHParameters):
        """
        Deserialize a tree from dictionary format and attach local private key if available.
        Used by joining peer to reconstruct group tree after join.
        """
        def walk(data, parent=None):
            node = TreeNode(is_leaf=data.get("is_leaf", False))
            node.member = data.get("member")
            node._has_blinded_key = data.get("has_blinded_key", False)

            # Deserialize public key or use frozen
            public_b64 = data.get("public_key")
            if public_b64:
                try:
                    public_bytes = base64.b64decode(public_b64)
                    node.public_key = serialization.load_pem_public_key(public_bytes, backend=default_backend())
                except Exception:
                    node.public_key = None

            frozen_b64 = data.get("frozen_public_key")
            if frozen_b64:
                node.frozen_public_key = base64.b64decode(frozen_b64)

            if node.member == local_member:
                node.private_key = None  # will be attached manually later

            node.parent = parent

            if "left" in data:
                node.left = walk(data["left"], parent=node)
            if "right" in data:
                node.right = walk(data["right"], parent=node)

            return node

        tree = cls()
        tree.root = walk(tree_data["root"])
        tree.members = tree_data.get("members", [])
        return tree

    def iter_leaves(self):
        """Yield all leaf nodes (member nodes) in the tree."""
        def dfs(node):
            if not node:
                return
            if node.is_leaf:
                yield node
            else:
                yield from dfs(node.left)
                yield from dfs(node.right)

        return dfs(self.root)

    def get_leaf_by_member(self, member_name: str):
        """Find and return the leaf node corresponding to the member."""
        for node in self.iter_leaves():
            if node.member == member_name:
                return node
        return None

    def derive_deterministic_private_key(self, shared_secret: bytes, parameters: dh.DHParameters):
        """
        Deterministically derive a DH private key from a shared secret using fixed domain parameters.
        Used to reattach sponsor-side synthetic private keys.
        """
        try:
            int_value = int.from_bytes(shared_secret, byteorder="big")
            int_value = int_value % parameters.parameter_numbers().p  # keep it in DH field

            # Generate deterministic private key from int
            private_numbers = dh.DHPrivateNumbers(
                x=int_value,
                public_numbers=parameters.generate_private_key().public_key().public_numbers()
            )
            return private_numbers.private_key(default_backend())
        except Exception as e:
            print(f"[ERROR] Failed to derive deterministic key: {e}")
            return None
    
    def safe_refresh_path_with_blinded_keys(tree, leaf, dh_parameters):
        """
        Recompute the path from the given leaf node up to the root,
        attaching synthetic private keys at intermediate nodes if one side has a private key
        and the other has a public key.
        """
        node = leaf
        while node.parent:
            parent = node.parent
            left = parent.left
            right = parent.right

            if left and left.private_key and right and right.public_key:
                try:
                    shared_secret = left.private_key.exchange(right.public_key)
                    synthetic_priv = TreeNode.derive_deterministic_private_key(shared_secret, dh_parameters)
                    parent.private_key = synthetic_priv
                    parent.public_key = synthetic_priv.public_key()
                    parent.shared_key = hashlib.sha256(shared_secret).digest()
                    print(f"[DEBUG] Synthetic key derived from left->right at node {id(parent)}")
                except Exception as e:
                    print(f"[ERROR] Failed to recompute blinded key at parent: {e}")

            elif right and right.private_key and left and left.frozen_public_key and left.public_key:
                try:
                    shared_secret = right.private_key.exchange(left.public_key)
                    synthetic_priv = TreeNode.derive_deterministic_private_key(shared_secret, dh_parameters)
                    parent.private_key = synthetic_priv
                    parent.public_key = synthetic_priv.public_key()
                    parent.shared_key = hashlib.sha256(shared_secret).digest()
                    print(f"[DEBUG] Synthetic key derived from right->left at node {id(parent)}")
                except Exception as e:
                    print(f"[ERROR] Failed to recompute blinded key at parent: {e}")
            else:
                print(f"[DEBUG] Skipped node {id(parent)}: neither child has private+public key")

            node = parent

    def safe_refresh_all(tree, dh_parameters):
        """
        Walk the entire tree bottom-up and rederive synthetic private keys where possible.
        Protects externally blinded keys by skipping frozen nodes.
        """
        def recurse(node):
            if not node or node.is_leaf:
                return

            recurse(node.left)
            recurse(node.right)

            left, right = node.left, node.right

            if left and right:
                if left.private_key and right.public_key:
                    shared_secret = left.private_key.exchange(right.public_key)
                elif right.private_key and left.public_key:
                    shared_secret = right.private_key.exchange(left.public_key)
                else:
                    return  # skip

                if node.private_key is None:  # don't overwrite
                    synthetic_priv = TreeNode.derive_deterministic_private_key(shared_secret, dh_parameters)
                    node.private_key = synthetic_priv
                    node.public_key = synthetic_priv.public_key()
                    node.shared_key = hashlib.sha256(shared_secret).digest()
                    print(f"[DEBUG] Global synthetic key derived at node {id(node)}")

        recurse(tree.root)
