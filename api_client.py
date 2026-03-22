# api_client.py
import cryptography, base64, requests, sys, secrets, hashlib, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryp_hpke import simple_hpke_seal, simple_hpke_open
from flask import session
from app import user_crypto_store

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.RatchetTree import RatchetTree, RatchetNode, LeafNode
#from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, SenderType, ContentType, WireFormat, ExtensionType
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._proposal import Add
from mls_stuff.MLS._commit import Commit
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.MLS import MLSMessage, Sender, AuthenticatedContent, FramedContent, FramedContentAuthData
from mls_stuff.Misc import VLBytes, SignContent, KDFLabel
from mls_stuff.Crypto._crypt_with_label import SignWithLabel
from mls_stuff.Crypto import GroupSecrets, EncryptedGroupSecrets, HPKECiphertext, ExtractWelcomeSecret, ExpandWithLabel, ExtractPSKSecret
from mls_stuff.Objects import GroupContext, GroupInfo
from mls_stuff.Crypto._derive_secrets import DeriveSecret
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey



        


cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

BASE_URL = "http://localhost:8000"  # Your FastAPI backend URL

# ============ USER MANAGEMENT ============

def register_user(username: str, password: str):
    """Register a new user"""
    try:
        response = requests.post(
            f"{BASE_URL}/users",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Register failed: {str(e)}")
        return {"error": str(e)}

def get_group_details(group_id_b64: str, token: str):
    """Get detailed information about a group from FastAPI"""
    try:
        import base64
        import requests
        
        # Convert to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        url = f"{BASE_URL}/groups/{group_id_hex}"
        print(f"📡 Fetching group details from: {url}")
        
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Got group details - epoch: {data.get('last_epoch')}")
            return data
        else:
            print(f"❌ Failed to get group details: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return {"error": str(e)}

    
def login_user(username: str, password: str):
    """Login user and get token"""
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Login failed: {str(e)}")
        return {"error": str(e)}

def get_user_by_username(username: str):
    """Get user information by username"""
    try:
        response = requests.get(
            f"{BASE_URL}/users?username={username}",
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        data = response.json()
        users = data.get('users', [])
        return users[0] if users else None
    except Exception as e:
        print(f"Get user by username failed: {str(e)}")
        return None

# ============ KEY PACKAGE MANAGEMENT ============

def upload_keypackage(user_id: str, key_package_bytes: bytes):
    """Upload a key package to the backend - old ones will be auto-deactivated"""
    try:
        response = requests.post(
            f"{BASE_URL}/key_packages/{user_id}",
            data=key_package_bytes,
            headers={"Content-Type": "application/octet-stream"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Upload keypackage failed: {str(e)}")
        return {"error": str(e)}

def get_latest_keypackage(user_id: str):
    """Get the latest key package for a user"""
    try:
        print(f"Fetching latest key package for user: {user_id}")
        response = requests.get(
            f"{BASE_URL}/key_packages/{user_id}/latest",
            headers={"Content-Type": "application/octet-stream"}
        )
        response.raise_for_status()
        print(f"✅ Got key package: {len(response.content)} bytes")
        return response.content
    except Exception as e:
        print(f"❌ Get latest keypackage failed: {str(e)}")
        return None

def mark_keypackage_used(ref_hash_hex: str):
    """Mark a key package as used"""
    try:
        response = requests.post(
            f"{BASE_URL}/key_packages/mark-used",
            json={"ref_hash": ref_hash_hex},
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Mark keypackage used failed: {str(e)}")
        return {"error": str(e)}

# ============ GROUP MANAGEMENT ============

def create_group(group_name: str, cipher_suite: int, token: str, group_id_b64: str = None):
    """Create a new MLS group"""
    try:
        payload = {
            "group_name": group_name,
            "cipher_suite": cipher_suite
        }
        
        # If group_id_b64 is provided, convert to hex for URL/JSON
        if group_id_b64:
            group_id_bytes = base64.b64decode(group_id_b64)
            group_id_hex = group_id_bytes.hex()
            payload["group_id"] = group_id_hex  # Send hex, not base64!
        
        print(f"Creating group with hex ID: {group_id_hex if group_id_b64 else 'auto'}")
        
        response = requests.post(
            f"{BASE_URL}/groups",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Create group failed: {str(e)}")
        return {"error": str(e)}


def get_my_groups(token: str):
    """Get all groups for the current user from FastAPI"""
    try:
        print(f"📡 Fetching groups from FastAPI...")
        
        response = requests.get(
            f"{BASE_URL}/users/me/groups",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved {len(data.get('groups', []))} groups")
            return data
        else:
            print(f"❌ Failed to get groups: {response.status_code}")
            return {"error": f"HTTP {response.status_code}", "groups": []}
            
    except requests.exceptions.Timeout:
        print("❌ Timeout fetching groups")
        return {"error": "Timeout", "groups": []}
    except requests.exceptions.ConnectionError:
        print("❌ Connection error fetching groups")
        return {"error": "Connection error", "groups": []}
    except Exception as e:
        print(f"❌ Error fetching groups: {str(e)}")
        return {"error": str(e), "groups": []}
    
def create_group(group_name: str, cipher_suite: int, token: str, group_id_b64: str = None):
    """Create a new MLS group in the FastAPI backend"""
    try:
        import base64
        import requests
        
        print(f"\n🔍 CREATE GROUP DEBUG:")
        print(f"  - group_name: {group_name}")
        print(f"  - cipher_suite: {cipher_suite}")
        print(f"  - group_id_b64: {group_id_b64}")
        
        payload = {
            "group_name": group_name,
            "cipher_suite": cipher_suite
        }
        
        # If group_id_b64 is provided, convert to bytes and verify length
        if group_id_b64:
            # Decode base64 to bytes
            group_id_bytes = base64.b64decode(group_id_b64)
            print(f"  - Decoded bytes length: {len(group_id_bytes)} bytes")
            print(f"  - Bytes hex: {group_id_bytes.hex()}")
            
            # VERIFY: Must be 16 bytes
            if len(group_id_bytes) != 16:
                print(f"❌ ERROR: group_id is {len(group_id_bytes)} bytes, must be 16 bytes")
                return {"error": f"Invalid group_id length: {len(group_id_bytes)} bytes, must be 16"}
            
            # IMPORTANT: FastAPI might expect base64 string, not hex!
            # Option 1: Send as base64 string (original format)
            payload["group_id"] = group_id_b64  # Send original base64
            print(f"  - Sending as base64: {group_id_b64}")
            
            # Option 2: Send as hex string (if your FastAPI expects hex)
            # payload["group_id"] = group_id_bytes.hex()
            # print(f"  - Sending as hex: {group_id_bytes.hex()}")
        
        url = f"{BASE_URL}/groups"
        print(f"  - URL: {url}")
        print(f"  - Full payload: {payload}")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        
        response = requests.post(url, json=payload, headers=headers)
        print(f"  - Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"  - Response: {result}")
            print(f"✅ Group created successfully")
            return result
        else:
            error_text = response.text
            print(f"❌ Error response: {error_text}")
            return {"error": f"HTTP {response.status_code}: {error_text}"}
            
    except base64.binascii.Error as e:
        print(f"❌ Base64 error: {str(e)}")
        return {"error": f"Invalid base64: {str(e)}"}
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

    
# ============ MESSAGE MANAGEMENT ============

def send_message(group_id: str, ciphertext: str, nonce: str, epoch: int, token: str):
    """Store an encrypted message"""
    try:
        payload = {
            "group_id": group_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "epoch": epoch,
            "content_type": 1,  # application message
            "wire_format": 1     # private message
        }
        
        response = requests.post(
            f"{BASE_URL}/messages",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Send message failed: {str(e)}")
        return {"error": str(e)}

def get_group_messages(group_id_b64: str, token: str, since_epoch: int = None):
    """Get messages - using hex in URL"""
    try:
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        url = f"{BASE_URL}/groups/{group_id_hex}/messages"
        params = {"limit": 100}
        if since_epoch:
            params["since_epoch"] = since_epoch
            
        response = requests.get(url, params=params, headers={"Authorization": f"Bearer {token}"})
        return response.json()
    except Exception as e:
        return {"error": str(e)}
    
# ============ CLEANUP ============

def cleanup_expired():
    """Run cleanup of expired packages"""
    try:
        response = requests.post(f"{BASE_URL}/cleanup")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Cleanup failed: {str(e)}")
        return {"error": str(e)}

def delete_user(user_id: str, token: str):
    """Delete a user account"""
    try:
        response = requests.delete(
            f"{BASE_URL}/users/{user_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return {"success": True}
    except Exception as e:
        print(f"Delete user failed: {str(e)}")
        return {"error": str(e)}
    

def create_group_with_id(group_name: str, cipher_suite: int, token: str, group_id_b64: str):
    """Create a group with a specific ID"""
    try:
        payload = {
            "group_name": group_name,
            "cipher_suite": cipher_suite,
            "group_id": group_id_b64
        }
        response = requests.post(
            f"{BASE_URL}/groups",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def store_epoch_secret(group_id_b64: str, epoch: int, epoch_secret: bytes, token: str):
    print(f"\n=== Storing epoch secret for group {group_id_b64} epoch {epoch} ===")
    
    import base64
    import requests

    # Convert base64 → bytes → hex
    group_id_bytes = base64.b64decode(group_id_b64)
    group_id_hex = group_id_bytes.hex()   # ← this is what you want

    url = f"{BASE_URL}/groups/{group_id_hex}/epoch-secret"
    
    payload = {
        "epoch": epoch,
        "epoch_secret": base64.b64encode(epoch_secret).decode('ascii')
    }

    print(f"→ URL: {url}")
    print(f"→ Payload keys: {list(payload.keys())}")

    try:
        r = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        print("SUCCESS: Epoch secret stored")
        print("Response:", r.json())
        return True
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response text:", e.response.text)
        return False

 
def update_group_epoch(group_id: str, new_epoch: int, token: str, epoch_secret: bytes = None):

    import base64
    import requests

    print(f"\n=== Updating group {group_id} to epoch {new_epoch} ===")
    # Convert base64 to hex for URL
    group_id_bytes = base64.b64decode(group_id)
    group_id_hex = group_id_bytes.hex()

    url = f"{BASE_URL}/groups/{group_id_hex}/epoch"
    payload = {"new_epoch": new_epoch}

    if epoch_secret:
        payload["epoch_secret"] = base64.b64encode(epoch_secret).decode('ascii')

        try:
            r = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            print("SUCCESS: Group epoch updated")
            print("Response:", r.json())
            return True
        except Exception as e:
            print("FAILED:", str(e))
            return False

    else:
        print("No epoch_secret provided, skipping update")
        return False


def insert_welcome(group_id_b64: str, new_member_id: str, welcome_bytes: bytes, token: str):
    try:
        # Convert base64 to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        url = f"{BASE_URL}/groups/{group_id_hex}/welcome"  # ← hex in path
        
        payload = {
            "to_user_id": new_member_id,
            "welcome_b64": base64.b64encode(welcome_bytes).decode('ascii')
        }

        print(f"→ Sending to: {url}")
        print(f"→ to_user_id: {new_member_id}")
        print(f"→ welcome_b64 length: {len(payload['welcome_b64'])} chars")

        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        print(f"✅ Welcome stored: {response.json()}")
        return response.json()
    
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP {e.response.status_code}: {e.response.text}")
        return {"error": f"{e.response.status_code} - {e.response.text}"}
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
        return {"error": str(e)}

def get_group_members(group_id_b64: str, token: str):
    """Get group members - using hex in URL"""
    print(f"\n=== Getting members for group {group_id_b64} ===")
    
    try:
        import base64
        import requests
        
        # Convert base64 to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()

        #url = f"{BASE_URL}/groups/{group_id_b64}/members"
        
        url = f"{BASE_URL}/groups/{group_id_hex}/members"
        print(f"URL: {url}")
        
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Found {len(data.get('members', []))} members")
            return data
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return {"error": str(e)}

def add_group_member(group_id_b64: str, user_id: str, leaf_index: int, token: str):
    """Add a member to a group - using hex in URL"""
    print(f"\n=== Adding member to group {group_id_b64} ===")
    
    try:
        import base64
        import requests
        
        # Convert base64 to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        url = f"{BASE_URL}/groups/{group_id_hex}/members"
        print(f"URL: {url}")
        
        payload = {
            "user_id": user_id,
            "leaf_index": leaf_index
        }
        
        response = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            print(f"✅ Member {user_id} added at leaf {leaf_index}")
            return response.json()
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return {"error": str(e)}

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

def add_member(group, new_member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    print(f"\n=== Adding {new_member_id} to group ===\n")

    if 'group_id_b64' not in group and 'group_id' in group:
        group_id_bytes = group['group_id'].data
        group['group_id_b64'] = base64.b64encode(group_id_bytes).decode('ascii')

    # 1. Fetch new member's KeyPackage
    new_kp_bytes = get_latest_keypackage(new_member_id)
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

    # 12. Prepare real GroupSecrets (this part you already have almost right)
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),   # the real derived one
        psks=[],                                # no PSKs yet
        path_secret=None                        # no path → no path_secret
    )

    group_secrets_bytes = group_secrets.serialize()

    # 13. HPKE-encrypt GroupSecrets to the NEW MEMBER only
    #    We need to do HPKE ourselves — library doesn't provide it

    # Get the init_key public key from the KeyPackage we used to add this member
    init_key_data = new_kp.content.init_key.data
    if isinstance(init_key_data, bytearray):
        init_key_data = bytes(init_key_data)

    # 13. HPKE-encrypt GroupSecrets to the NEW MEMBER only

    init_pub = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(
        bytes(new_kp.content.init_key.data)
    )

    kem_output, ciphertext = simple_hpke_seal(
        init_pub,
        b"MLS 1.0 external init secret",   # ← literal bytes, no extra
        group_secrets_bytes
    )

    print(f"HPKE kem_output len: {len(kem_output)}")      # should be 32
    print(f"HPKE ciphertext len: {len(ciphertext)}")      # should be group_secrets_bytes len + 16

    encrypted_group_secrets = EncryptedGroupSecrets(
        new_member=VLBytes(new_kp.reference_hash(cs)),     # ← fixed here
        encrypted_group_secrets=HPKECiphertext(
            kem_output=VLBytes(kem_output),
            ciphertext=VLBytes(ciphertext)
        )
    )

    # 3. Create GroupInfo (what new member needs to reconstruct context + tree)
    #    You need confirmation_tag — for simple add without update path it's often the MAC over confirmed transcript
    #    Minimal / dummy for now (in real impl compute properly)
    #confirmation_tag = b""   # TODO: compute real one later (usually HMAC)
     
    # Better approximation of confirmation tag
    confirmed_data = b"confirmation" + authenticated_content.serialize()
    confirmation_tag = hashlib.sha256(confirmed_data).digest()

    group_info = GroupInfo(
        group_context=group["group_context"],
        confirmation_tag=VLBytes(confirmation_tag),
        signer=0,  # committer's leaf index
        signature=VLBytes(b""),
        extensions=[]
    )

    group_info_bytes = group_info.serialize()

    # 4. Encrypt GroupInfo using AES-128-GCM (matching the ciphersuite)
    # 4. Encrypt GroupInfo (using welcome_secret derived from joiner_secret)
    #    → this uses the same logic as .decrypt_group_info() but in reverse

    #psk_secret = bytes(cs.hash_size)  # zeros if no PSK
    psk_secret = bytes(32)
    welcome_secret = ExtractWelcomeSecret(
        cs,
        joiner_secret,
        psk_secret
    )

    # Fixed AEAD sizes for AES-128-GCM
    AEAD_KEY_SIZE   = 16
    AEAD_NONCE_SIZE = 12

    print(f"Expected welcome_key length: {AEAD_KEY_SIZE}")
    print(f"Expected welcome_nonce length: {AEAD_NONCE_SIZE}")

    nonce_label = KDFLabel(AEAD_NONCE_SIZE, b"nonce")
    key_label   = KDFLabel(AEAD_KEY_SIZE, b"key")

    welcome_nonce = ExpandWithLabel(cs, welcome_secret, nonce_label)
    welcome_key   = ExpandWithLabel(cs, welcome_secret, key_label)

    # Debug the actual lengths
    print(f"Actual welcome_key length: {len(welcome_key)}")
    print(f"Actual welcome_nonce length: {len(welcome_nonce)}")

    aead = AESGCM(welcome_key)
    encrypted_group_info_cipher = aead.encrypt(
        nonce=welcome_nonce,
        data=group_info_bytes,
        associated_data=b""
    )

    encrypted_group_info = VLBytes(encrypted_group_info_cipher)
    

    # 5. Build Welcome
    welcome = Welcome(
        cipher_suite=cs,
        secrets=[encrypted_group_secrets],
        encrypted_group_info=encrypted_group_info
    )

    # Wrap the Welcome in an MLSMessage first
    welcome_message = MLSMessage(
        wire_format=WireFormat.MLS_WELCOME,  # ← Use WELCOME format, not PUBLIC_MESSAGE!
        msg_content=welcome
    )
    welcome_bytes = welcome_message.serialize()

    print(f"Sent bytes first 8: {welcome_bytes[:8].hex()}")
    print(f"  version/cipher_suite/wire_format?: {welcome_bytes[0:1].hex()} {welcome_bytes[1:3].hex()} {welcome_bytes[3:4].hex()}")

    print(f"  - Generated real Welcome ({len(welcome_bytes)} bytes)")
    print(f"  - secrets count: {len(welcome.secrets)}")
    print(f"  - encrypted_group_info len: {len(encrypted_group_info)}")

    return welcome

async def process_pending_welcomes(priv_bytes: bytes, token: str):
    """
    Process all pending welcome messages for a user using the library's built-in decryption
    """
    print("\n📨 Processing all pending welcomes...")
    
    try:
        # 1. Fetch pending welcomes from the server
        resp = requests.get(f"{BASE_URL}/pending-welcomes", headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        
        data = resp.json()
        welcomes = data.get("welcomes", [])
        
        if not welcomes:
            print("   No pending welcomes")
            return []
        
        print(f"   Found {len(welcomes)} pending welcomes")
        
        joined_groups = []
        
        # 2. Process each welcome
        for item in welcomes:
            try:
                welcome_b64 = item["welcome_b64"]
                group_id_b64 = item.get("group_id")  # if available
                
                print(f"\n   Processing welcome for group: {group_id_b64}")
                
                # Decode welcome
                welcome_bytes = base64.b64decode(welcome_b64)
                welcome = Welcome.deserialize(bytearray(welcome_bytes))
                
                # Get cipher suite from welcome
                cs = welcome.cipher_suite
                
                # Find the encrypted secret for this user
                if not welcome.secrets:
                    print("   ⚠️ No secrets in welcome, skipping")
                    continue
                
                # Assume first secret (in production, match by ref_hash)
                encrypted_secret = welcome.secrets[0]
                
                # === USE LIBRARY'S DECRYPT METHOD - NOT simple_hpke_open! ===
                group_secrets = encrypted_secret.decrypt(
                    cipher_suite=cs,
                    private_key=priv_bytes,
                    encrypted_group_info=bytes(welcome.encrypted_group_info.data)
                )
                
                joiner_secret = group_secrets.joiner_secret.to_bytes()
                print(f"   ✅ GroupSecrets decrypted, joiner: {joiner_secret[:16].hex()}...")
                
                # Decrypt GroupInfo
                group_info = welcome.decrypt_group_info(
                    joiner_secret=joiner_secret,
                    psk_secret=bytes(32)  # no PSK
                )
                
                print(f"   ✅ GroupInfo decrypted successfully")
                
                # Extract group data
                ctx = group_info.group_context
                group_id_bytes = ctx.group_id.to_bytes()
                epoch = ctx.epoch
                
                # Try to load ratchet tree from extensions
                from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
                from mls_stuff.Enums import ExtensionType
                
                tree = RatchetTree()
                tree_found = False
                
                if hasattr(group_info, 'extensions') and group_info.extensions:
                    for ext in group_info.extensions:
                        if ext.extension_type == ExtensionType.ratchet_tree:
                            tree_data = bytes(ext.extension_data.data)
                            tree = RatchetTree.deserialize(bytearray(tree_data))
                            print(f"   ✅ Ratchet tree loaded ({len(tree_data)} bytes)")
                            tree_found = True
                            break
                
                if not tree_found:
                    print(f"   ⚠️ No ratchet tree found, initializing empty")
                    tree.extend()
                    tree.extend()
                
                # Derive epoch secret
                from mls_stuff.Crypto._derive_secrets import DeriveSecret
                epoch_secret = DeriveSecret(cs, joiner_secret, b"epoch")
                
                # Build group state
                import base64
                import time
                
                group_state = {
                    "group_id": group_id_bytes,
                    "group_id_b64": base64.b64encode(group_id_bytes).decode('ascii'),
                    "epoch": epoch,
                    "tree": tree,
                    "group_context": ctx,
                    "group_info": group_info,
                    "epoch_secret": epoch_secret,
                    "joiner_secret": joiner_secret,
                    "cipher_suite": cs,
                    "joined_at": time.time()
                }
                
                print(f"   ✅ Successfully joined group: {group_state['group_id_b64']}")
                joined_groups.append(group_state)
                
            except Exception as e:
                print(f"   ❌ Failed to process welcome: {str(e)}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"\n✅ Processed {len(joined_groups)}/{len(welcomes)} welcomes successfully")
        return joined_groups
        
    except Exception as e:
        print(f"❌ Failed to fetch pending welcomes: {str(e)}")
        return []
    
def get_pending_welcomes(token: str):
    """Get pending welcome messages for the current user from FastAPI"""
    try:
        print(f"📡 Fetching pending welcomes from FastAPI...")
        
        response = requests.get(
            f"{BASE_URL}/pending-welcomes",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved {len(data.get('welcomes', []))} pending welcomes")
            return data
        else:
            print(f"❌ Failed to get welcomes: {response.status_code}")
            return {"error": f"HTTP {response.status_code}", "welcomes": []}
            
    except Exception as e:
        print(f"❌ Error fetching welcomes: {str(e)}")
        return {"error": str(e), "welcomes": []}    
        

    
    except Exception as e:
        print(f"❌ Processing failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

def check_epoch_secrets(group_id_b64: str, token: str):
    """Check what epoch secrets exist in the database"""
    import base64
    import requests
    
    group_id_bytes = base64.b64decode(group_id_b64)
    group_id_hex = group_id_bytes.hex()
    
    # First, check the groups table to see current epoch
    group_url = f"{BASE_URL}/groups/{group_id_hex}"
    group_response = requests.get(group_url, headers={"Authorization": f"Bearer {token}"})
    
    # Then check epoch_secrets table
    # You might need an endpoint to query epoch secrets
    print("\n📊 EPOCH SECRETS DIAGNOSTIC")
    print("="*50)
    
    if group_response.status_code == 200:
        group_data = group_response.json()
        print(f"Group: {group_data.get('group_name')}")
        print(f"Current epoch in groups table: {group_data.get('last_epoch')}")
    
    # Query epoch_secrets directly (if you have an endpoint)
    secrets_url = f"{BASE_URL}/groups/{group_id_hex}/epoch-secrets"
    secrets_response = requests.get(secrets_url, headers={"Authorization": f"Bearer {token}"})
    
    if secrets_response.status_code == 200:
        secrets_data = secrets_response.json()
        epochs = secrets_data.get('epochs', [])
        print(f"Epoch secrets stored: {epochs}")
        print(f"Count: {len(epochs)}")
    else:
        print("No epoch secrets endpoint or error accessing")
    
    return {
        'group_epoch': group_data.get('last_epoch') if group_response.status_code == 200 else None,
        'stored_epochs': epochs if secrets_response.status_code == 200 else []
    }


def process_single_welcome(private_key: bytes, welcome_b64: str, group_id_b64: str): 
#process_single_welcome(private_key: bytes, welcome_b64: str, group_id_b64: str) -> Dict[str, Any]:
    
    """
    Process a single MLS Welcome message and join the group.
    
    Args:
        private_key: The X25519 init private key (bytes) matching the KeyPackage ref in the Welcome
        welcome_b64: Base64-encoded MLSMessage containing the Welcome
        group_id_b64: Base64-encoded group ID (for logging/validation)

    Returns:
        Dict with 'success', group state, or 'error'
    """
    try:
        print(f"\n=== Processing Welcome for group {group_id_b64} ===")
        print(f"   Welcome b64 length: {len(welcome_b64)} chars")

        # 1. Decode base64 → bytes
        welcome_bytes = base64.b64decode(welcome_b64)
        print(f"   Received bytes length: {len(welcome_bytes)}")
        print(f"   First 16 bytes: {welcome_bytes[:16].hex()}")

        # 2. Parse as MLSMessage (your logs show wire_format=MLS_WELCOME)
        mls_msg = MLSMessage.deserialize(bytearray(welcome_bytes))
        print(f"   Parsed MLSMessage → wire_format = {mls_msg.wire_format}")

        if not hasattr(mls_msg, 'msg_content') or not isinstance(mls_msg.msg_content, Welcome):
            return {"error": "MLSMessage does not contain a Welcome object"}

        welcome = mls_msg.msg_content
        print(f"   Welcome extracted → {len(welcome_bytes)} bytes, {len(welcome.secrets)} secrets")

        if not welcome.secrets:
            return {"error": "Welcome contains no EncryptedGroupSecrets"}

        # 3. Get cipher suite early — needed for later derivations
        cipher_suite = welcome.cipher_suite
        print(f"   Cipher suite: {cipher_suite.name}")

        # 4. Take the first (and usually only) encrypted secret
        encrypted_secret = welcome.secrets[0]
        key_package_ref = encrypted_secret.new_member.to_bytes().hex()
        print(f"   KeyPackage ref: {key_package_ref[:16]}...")

        # 5. Plain HPKE decryption of GroupSecrets (MLS base mode)
        enc_gs = encrypted_secret.encrypted_group_secrets

        kem_output_bytes = bytes(enc_gs.kem_output.data)
        ciphertext_bytes = bytes(enc_gs.ciphertext.data)

        print("   Attempting plain HPKE open (MLS spec compliant)")
        print(f"     info string hex: {'MLS 1.0 external init secret'.encode().hex()}")
        print(f"     kem_output[:16]: {kem_output_bytes[:16].hex()}")
        print(f"     ciphertext[:16]: {ciphertext_bytes[:16].hex()}")

        group_secrets_raw = simple_hpke_open(
            private_key,
            b"MLS 1.0 external init secret",
            kem_output_bytes,
            ciphertext_bytes
        )

        print(f"   HPKE decryption succeeded — got {len(group_secrets_raw)} bytes")
        print(f"     First 16 bytes of GroupSecrets: {group_secrets_raw[:16].hex()}")

        # 6. Deserialize GroupSecrets
        group_secrets = GroupSecrets.deserialize(bytearray(group_secrets_raw))

        # 7. Handle PSKs (currently none expected)
        psk_secret = bytes(32)  # zeros — no PSKs in your setup
        if group_secrets.psks:
            print(f"   Warning: {len(group_secrets.psks)} PSKs found — using default psk_secret")
            # In real code: look up actual PSKs and compute ExtractPSKSecret

        joiner_secret = group_secrets.joiner_secret.to_bytes()
        print(f"   Joiner secret (first 16): {joiner_secret[:16].hex()}...")

        # 8. Decrypt GroupInfo
        group_info = welcome.decrypt_group_info(
            joiner_secret=joiner_secret,
            psk_secret=psk_secret
            # Note: if your library version requires cipher_suite here, add it:
            # cipher_suite=cipher_suite
        )
        print("   GroupInfo decrypted successfully")

        # 9. Extract core group data
        group_context = group_info.group_context
        group_id_bytes = bytes(group_context.group_id.data)
        epoch = group_context.epoch

        print(f"   Group ID (hex): {group_id_bytes.hex()}")
        print(f"   Epoch: {epoch}")

        # After GroupInfo is decrypted
        group_context = group_info.group_context
        group_id_bytes = bytes(group_context.group_id.data)
        epoch = group_context.epoch

        epoch_secret = DeriveSecret(cipher_suite, joiner_secret, b"epoch")

        group_state = {
            "group_id": group_id_bytes,
            "group_id_b64": base64.b64encode(group_id_bytes).decode('ascii'),
            "epoch": epoch,
            "group_context": group_context,
            "epoch_secret": epoch_secret,
            "joiner_secret": joiner_secret,
            "cipher_suite": cipher_suite,
            "joined_at": time.time()
            # NO tree here anymore
        }

        print("\n=== Crypto part of join successful ===")
        print(f"   Group ID (b64): {group_state['group_id_b64']}")
        print(f"   Epoch: {epoch}")

        return {
            'success': True,
            'group_id_b64': group_state['group_id_b64'],
            'epoch': epoch,
            'group_state_crypto': group_state,   # renamed to make it clear
            'group_info' : group_info
        }

    except Exception as e:
        print(f"\n❌ Failed to process welcome: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

def mark_welcome_delivered(welcome_id: str, token: str):
    """Mark a welcome message as delivered"""
    print(f"--------------------------------------{welcome_id}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/welcome/{welcome_id}/delivered",
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Failed to mark welcome delivered: {str(e)}")
        return {"error": str(e)}
    
def debug_print(step, data):
    """Simple debug function"""
    print(f"\n🔍 DEBUG [{step}]: {data}")