from cryptography.hazmat.primitives.asymmetric import dh

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import base64


class TreeNode:
    """
    Represents a node in the Tree-based Group Diffie-Hellman (TGDH) key tree.
    Leaf nodes hold individual member keys.
    Intermediate nodes derive shared secrets between children.
    """

    def __init__(self, is_leaf=False):
        self.private_key: dh.DHPrivateKey = None
        self.public_key: dh.DHPublicKey = None
        self.shared_key: bytes = None

        self.left: TreeNode = None
        self.right: TreeNode = None
        self.parent: TreeNode = None

        self.is_leaf = is_leaf
        self.member: str = None  # only used for leaves

        self.frozen_public_key: bool = False  
        self._skip_refresh: bool = False  # skip recompute during sponsor refresh if set
        self._has_blinded_key: bool = False  # marks externally computed blinded public key

    def generate_keys(self, parameters):
        """Generate a new DH key pair using provided DH parameters."""
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def compute_shared_key(self):
        if not self.left or not self.right:
            print("[ERROR] Cannot compute shared key: missing children.")
            return

        if not self.left.public_key or not self.right.public_key:
            print("[ERROR] Cannot compute shared key: one or both child public keys missing.")
            return

        # Use the private key from one child and the public key from the other
        try:
            if self.left.private_key and self.right.public_key:
                private = self.left.private_key
                peer_pub = self.right.public_key
            elif self.right.private_key and self.left.public_key:
                private = self.right.private_key
                peer_pub = self.left.public_key
            else:
                print("[ERROR] Cannot compute shared key: no child has a private key.")
                return

            # Perform DH exchange
            shared_secret = private.exchange(peer_pub)
            self.shared_key = hashlib.sha256(shared_secret).digest()

            # Derive blinded public key from shared secret
            self.public_key = self._derive_blinded_key(shared_secret)

        except Exception as e:
            print(f"[ERROR] Failed to compute shared key: {e}")

    def _derive_blinded_key(self, shared_secret):
        """Generate a blinded DH public key from the shared secret."""
        try:
            parameters = self.left.public_key.parameters()
            synthetic_priv = self.derive_deterministic_private_key(shared_secret, parameters)
            return synthetic_priv.public_key()
        except Exception as e:
            print(f"[ERROR] Failed to derive blinded key: {e}")
            return None


    def sibling(self):
        """Return the sibling node (left/right of current node)."""
        if not self.parent:
            return None
        return self.parent.left if self.parent.right is self else self.parent.right

    def serialize_public_key(self):
        """Serialize this node’s public key to a base64 PEM format."""
        if self.public_key is None:
            return None
        try:
            return base64.b64encode(
                self.public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode()
        except Exception as e:
            print(f"[ERROR] Failed to serialize public key: {e}")
            return None

    def serialize_private_key(self):
        """Serialize this node’s private key to a base64 PEM format (used only locally)."""
        if self.private_key is None:
            return None
        try:
            return base64.b64encode(
                self.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
            ).decode()
        except Exception as e:
            print(f"[ERROR] Failed to serialize private key: {e}")
            return None

    @staticmethod
    def derive_deterministic_private_key(shared_secret, dh_parameters):
        """Derive a synthetic private key deterministically from a shared secret."""
        seed = hashlib.sha256(shared_secret).digest()
        param_numbers = dh_parameters.parameter_numbers()
        private_value = int.from_bytes(seed, "big") % param_numbers.p

        public_numbers = dh.DHPublicNumbers(
            pow(param_numbers.g, private_value, param_numbers.p),
            param_numbers
        )
        private_numbers = dh.DHPrivateNumbers(private_value, public_numbers)
        return private_numbers.private_key(default_backend())
