from .binary_key_tree import BinaryKeyTree

class ChatModel:
    """
    Central state holder for group key trees across different chat groups.
    Each group is identified by name and mapped to a BinaryKeyTree instance.
    """

    def __init__(self):
        self.group_trees: dict[str, BinaryKeyTree] = {}

    def create_group_tree(self, group_name: str):
        """
        Initialize an empty BinaryKeyTree for a new group.
        """
        if group_name not in self.group_trees:
            self.group_trees[group_name] = BinaryKeyTree()

    def get_group_tree(self, group_name: str) -> BinaryKeyTree:
        """
        Retrieve the BinaryKeyTree associated with the given group.
        """
        return self.group_trees.get(group_name)

    def get_latest_tree(self) -> BinaryKeyTree:
        """
        Return the most recently used group tree, if any exist.
        Used for fallback lookups.
        """
        if self.group_trees:
            return list(self.group_trees.values())[-1]
        return None
    
    def get_group_key(self, group_name: str):
        """
        Return the group key (shared root key) for a given group name,
        or None if the group or key is not yet available.
        """
        tree = self.group_trees.get(group_name)
        return tree.root.shared_key if tree and tree.root and tree.root.shared_key else None
