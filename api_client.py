# api_client.py
import cryptography, base64, requests, sys, secrets, hashlib, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import api_client_2
from cryp_hpke import simple_hpke_seal, simple_hpke_open
from flask import session
from app import user_crypto_store
from typing import List

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
        #print(f"Register failed: {str(e)}")
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
        #print(f"📡 Fetching group details from: {url}")
        
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            #print(f"✅ Got group details - epoch: {data.get('last_epoch')}")
            return data
        else:
            #print(f"❌ Failed to get group details: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        #print(f"❌ Error: {str(e)}")
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
        #print(f"Login failed: {str(e)}")
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
        #print(f"Get user by username failed: {str(e)}")
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
        #print(f"Upload keypackage failed: {str(e)}")
        return {"error": str(e)}

def get_latest_keypackage(user_id: str):
    """Get the latest key package for a user"""
    try:
        #print(f"Fetching latest key package for user: {user_id}")
        response = requests.get(
            f"{BASE_URL}/key_packages/{user_id}/latest",
            headers={"Content-Type": "application/octet-stream"}
        )
        response.raise_for_status()
        #print(f"✅ Got key package: {len(response.content)} bytes")
        return response.content
    except Exception as e:
        #print(f"❌ Get latest keypackage failed: {str(e)}")
        return None

# ============ GROUP MANAGEMENT ============

def get_my_groups(token: str):
    """Get all groups for the current user from FastAPI"""
    try:
        #print(f"📡 Fetching groups from FastAPI...")
        
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
            #print(f"✅ Retrieved {len(data.get('groups', []))} groups")
            return data
        else:
            #print(f"❌ Failed to get groups: {response.status_code}")
            return {"error": f"HTTP {response.status_code}", "groups": []}
            
    except requests.exceptions.Timeout:
        #print("❌ Timeout fetching groups")
        return {"error": "Timeout", "groups": []}
    except requests.exceptions.ConnectionError:
        #print("❌ Connection error fetching groups")
        return {"error": "Connection error", "groups": []}
    except Exception as e:
        #print(f"❌ Error fetching groups: {str(e)}")
        return {"error": str(e), "groups": []}

def get_epoch_secret(group_id_b64: str, epoch: int, token: str):
    """Get epoch secret from the database"""
    try:
        import base64
        import requests
        
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        url = f"{BASE_URL}/groups/{group_id_hex}/epoch-secrets/{epoch}"
        #print(f"📡 Fetching epoch secret from: {url}")
        
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        
        if response.status_code == 200:
            return response.json()
        else:
            #print(f"❌ Failed to get epoch secret: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        #print(f"❌ Error getting epoch secret: {str(e)}")
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
        #print(f"Send message failed: {str(e)}")
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
    #print(f"\n=== Storing epoch secret for group {group_id_b64} epoch {epoch} ===")
    
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

    #print(f"→ URL: {url}")
    #print(f"→ Payload keys: {list(payload.keys())}")

    try:
        r = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        #print("SUCCESS: Epoch secret stored")
        #print("Response:", r.json())
        return True
    except Exception as e:
        #print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response text:", e.response.text)
        return False

 
def update_group_epoch(group_id: str, new_epoch: int, token: str):
    """Update group epoch - NO epoch_secret needed or sent!"""
    
    import base64
    import requests

    print(f"\n=== Updating group {group_id} to epoch {new_epoch} ===")
    
    # Convert base64 to hex for URL
    group_id_bytes = base64.b64decode(group_id)
    group_id_hex = group_id_bytes.hex()

    url = f"{BASE_URL}/groups/{group_id_hex}/epoch"
    
    # Only send new_epoch, NO epoch_secret
    payload = {"new_epoch": new_epoch}

    try:
        r = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        print("SUCCESS: Group epoch updated")
        print("Response:", r.json())
        return True
    except Exception as e:
        print(f"FAILED: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status: {e.response.status_code}")
            print(f"Response text: {e.response.text}")
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

        #print(f"→ Sending to: {url}")
        #print(f"→ to_user_id: {new_member_id}")
        #print(f"→ welcome_b64 length: {len(payload['welcome_b64'])} chars")

        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        #print(f"✅ Welcome stored: {response.json()}")
        return response.json()
    
    except requests.exceptions.HTTPError as e:
        #print(f"❌ HTTP {e.response.status_code}: {e.response.text}")
        return {"error": f"{e.response.status_code} - {e.response.text}"}
    except Exception as e:
        #print(f"❌ Failed: {str(e)}")
        return {"error": str(e)}

def get_group_members(group_id_b64: str, token: str):
    """Get group members - using hex in URL"""
    #print(f"\n=== Getting members for group {group_id_b64} ===")
    
    try:
        import base64
        import requests
        
        # Convert base64 to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()

        #url = f"{BASE_URL}/groups/{group_id_b64}/members"
        
        url = f"{BASE_URL}/groups/{group_id_hex}/members"
        #print(f"URL: {url}")
        
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            #print(f"✅ Found {len(data.get('members', []))} members")
            return data
        else:
            #print(f"❌ Failed: {response.status_code} - {response.text}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        #print(f"❌ FAILED: {str(e)}")
        return {"error": str(e)}

def add_group_member(group_id_b64: str, user_id: str, leaf_index: int, token: str):
    """Add a member to a group - using hex in URL"""
    #print(f"\n=== Adding member to group {group_id_b64} ===")
    
    try:
        import base64
        import requests
        
        # Convert base64 to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        url = f"{BASE_URL}/groups/{group_id_hex}/members"
        #print(f"URL: {url}")
        
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
            #print(f"✅ Member {user_id} added at leaf {leaf_index}")
            return response.json()
        else:
            #print(f"❌ Failed: {response.status_code} - {response.text}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        #print(f"❌ FAILED: {str(e)}")
        return {"error": str(e)}

def create_empty_group(creator_leaf_node: LeafNode, creator_name: str = "bob"):
    #print(f"\n=== {creator_name.capitalize()} creates empty group ===")

    # 1. Random group ID (public)
    group_id_bytes = secrets.token_bytes(16)
    group_id = VLBytes(group_id_bytes)
    #print("Group ID (hex):", group_id_bytes.hex())

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
    #print(f"Leaf 0 index after update: {tree[0]._leaf_index}")  # should be 0

    # 3. Generate the INITIAL EPOCH SECRET (32 bytes for AES-256)
    epoch_secret = secrets.token_bytes(32)  #  THIS IS THE EPOCH SECRET!
    #print(f"Initial epoch secret (first 16 bytes): {epoch_secret[:16].hex()}...")
    
    # 4. Generate init secret for next epoch
    init_secret = DeriveSecret(cs, epoch_secret, b"init")
    #print(f"Init secret (first 16 bytes): {init_secret[:16].hex()}...")

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

    #print("Empty group created successfully!")
    #print(f"  Epoch: 0")
    #print(f"  Members: ['{creator_name}']")
    #print(f"  Tree hash (prefix): {tree_hash.data.hex()[:32]}...")

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
    
def get_pending_welcomes(token: str):
    """Get pending welcome messages for the current user from FastAPI"""
    try:
        #print(f"📡 Fetching pending welcomes from FastAPI...")
        
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
            #print(f"✅ Retrieved {len(data.get('welcomes', []))} pending welcomes")
            return data
        else:
            #print(f"❌ Failed to get welcomes: {response.status_code}")
            return {"error": f"HTTP {response.status_code}", "welcomes": []}
            
    except Exception as e:
        #print(f"❌ Error fetching welcomes: {str(e)}")
        return {"error": str(e), "welcomes": []}    
        

def mark_welcome_delivered(welcome_id: str, token: str):
    """Mark a welcome message as delivered"""
    #print(f"--------------------------------------{welcome_id}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/welcome/{welcome_id}/delivered",
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        #print(f"❌ Failed to mark welcome delivered: {str(e)}")
        return {"error": str(e)}
    



def encrypt_and_send_message(group_id_b64: str, message_text: str, token: str, user_id: str, group_state: dict):
    try:
        print(f"\n{'='*60}")
        print(f"🔐 ENCRYPTING MESSAGE - User: {user_id[:8]}...")
        print(f"{'='*60}")
        
        # Get tree from group_state
        tree = group_state.get('tree')
        if tree is None:
            # Try to restore from serialized
            tree_b64 = group_state.get('tree_serialized')
            if tree_b64:
                tree_bytes = base64.b64decode(tree_b64)
                tree = RatchetTree.deserialize(bytearray(tree_bytes))
                print(f"   Restored tree from serialized ({len(tree.leaves)} leaves)")
                group_state['tree'] = tree
            else:
                return {"error": "No tree in group_state"}
        
        # Print tree details for this user
        tree_hash = api_client_2.get_tree_hash(tree, group_state['cipher_suite'])
        print(f"   🌲 Tree hash: {tree_hash[:16]}...")
        print(f"   🌲 Leaves count: {len(tree.leaves)}")
        print(f"   🌲 Nodes count: {tree.nodes}")
        
        # Verify leaf indices
        for i, leaf in enumerate(tree.leaves):
            if isinstance(leaf, LeafNode):
                if hasattr(leaf, '_leaf_index'):
                    print(f"   🌿 Leaf {i}: index={leaf._leaf_index}")
                else:
                    print(f"   🌿 Leaf {i}: NO _leaf_index!")
        
        # Derive epoch secret
        #epoch_secret = api_client_2.derive_epoch_secret_from_tree(tree, group_state['cipher_suite'])
        epoch_secret = group_state.get('epoch_secret')
        epoch = group_state.get('group_last_epoch', group_state.get('epoch', 0))
        my_leaf_index = group_state.get('my_leaf_index')
        cipher_suite = group_state['cipher_suite']
        group_id_bytes = base64.b64decode(group_id_b64)
        
        print(f"   Epoch: {epoch}")
        print(f"   My leaf index: {my_leaf_index}")
        print(f"   Message: {message_text[:50]}...")
        print(f"🔐 Encrypting message using derived epoch_secret (epoch {epoch})")

        sender = Sender(sender_type=SenderType.member, leaf_index=my_leaf_index)
        
        framed_content = FramedContent(
            group_id=VLBytes(group_id_bytes),
            epoch=epoch,
            sender=sender,
            authenticated_data=VLBytes(b""),
            content_type=ContentType.application,
            application_data=VLBytes(message_text.encode('utf-8'))
        )
        content_bytes = framed_content.serialize()
        message_key = DeriveSecret(cipher_suite, epoch_secret, b"message key")
        
        nonce = secrets.token_bytes(12)
        aead = AESGCM(message_key)
        ciphertext = aead.encrypt(nonce, content_bytes, b"")
        
        # 6. Store ONLY the ciphertext and nonce (NOT wrapped in MLSMessage!)
        payload = {
            "group_id": group_id_b64,
            "ciphertext": base64.b64encode(ciphertext).decode('ascii'),  # ← Only the encrypted content
            "nonce": base64.b64encode(nonce).decode('ascii'),           # ← The nonce
            "epoch": epoch,
            "content_type": 1,
            "wire_format": 2
        }
        
        #print(f"   ciphertext length: {len(ciphertext)}")
        #print(f"   nonce: {nonce.hex()}")
        
        response = requests.post(
            f"{BASE_URL}/messages",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            #print(f"✅ Message sent successfully")
            return {"success": True, "message": "Message sent"}
        else:
            return {"error": f"Server error: {response.text}"}
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

def decrypt_message(msg_data: dict, group_state: dict, user_id: str):
    try:
        #print(f" 🔓 Decrypting with tree(first 8 bytes): {group_state['tree'][:8]}")
        #epoch_secret = api_client_2.derive_epoch_secret_from_tree(group_state['tree'], group_state['cipher_suite'])
        epoch_secret = group_state.get('epoch_secret')
        cipher_suite = group_state['cipher_suite']
        epoch = msg_data.get('epoch', group_state.get('epoch', 0))

        print(f"Decrypting message - epoch {epoch}, sender: {msg_data.get('sender_username')}")

        message_key = DeriveSecret(cipher_suite, epoch_secret, b"message key")
        print(f"Message key (first 8 bytes): {message_key[:8].hex()}")

        ciphertext = base64.b64decode(msg_data['ciphertext'])
        nonce = base64.b64decode(msg_data['nonce'])

        aead = AESGCM(message_key)
        plaintext = aead.decrypt(nonce, ciphertext, b"")
        
        framed = FramedContent.deserialize(bytearray(plaintext))
        
        if hasattr(framed, 'application_data'):
            message_text = framed.application_data.data.decode('utf-8')
        else:
            message_text = "[No text]"

        return {
            'message_id': msg_data.get('message_id'),
            'sender_username': msg_data.get('sender_username', 'Unknown'),
            'sender_leaf_index': framed.sender.leaf_index,
            'text': message_text,
            'epoch': epoch,
            'created_at': msg_data.get('created_at')
        }
        
    except Exception as e:
        print(f"❌ Decryption failed: {type(e).__name__}: {e}")
        raise

# Add this function to api_client.py

def build_tree_by_replay(group_id_b64: str, token: str) -> tuple[RatchetTree, int, dict]:
    """
    Build the ratchet tree by replaying all member additions in order.
    This matches the working method from process_welcome.
    
    Returns: (tree, current_epoch, members_info)
    """
    print(f"\n🌲 Building tree by replay for group {group_id_b64}")
    
    # 1. Get all members from database (sorted by leaf_index)
    members_response = get_group_members(group_id_b64, token)
    if 'error' in members_response:
        raise ValueError(f"Failed to get members: {members_response['error']}")
    
    members = members_response.get('members', [])
    if not members:
        raise ValueError("No members found in group")
    
    members.sort(key=lambda m: m['leaf_index'])
    
    print(f"   Found {len(members)} members in database")
    for m in members:
        print(f"      Leaf {m['leaf_index']}: {m['username']}")
    
    # 2. Get creator's leaf node to initialize tree
    creator_id = members[0]['user_id']
    creator_kp_bytes = get_latest_keypackage(creator_id)
    if not creator_kp_bytes:
        raise ValueError("Creator key package not found")
    
    creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes))
    creator_leaf = creator_kp.content.leaf_node
    
    # 3. Create empty group using the working method
    temp_group = create_empty_group(creator_leaf, "temp")
    tree = temp_group['tree']
    epoch = 0
    
    print(f"   Created empty tree with {len(tree.leaves)} leaves")
    
    # 4. Replay all member additions (except creator)
    for member in members[1:]:  # Skip creator (leaf 0)
        member_id = member.get('user_id')
        member_name = member.get('username')
        leaf_index = member.get('leaf_index')
        
        print(f"   Replaying addition of {member_name} at leaf {leaf_index}")
        
        # Fetch member's KeyPackage
        member_kp_bytes = get_latest_keypackage(member_id)
        if not member_kp_bytes:
            print(f"   ⚠️ No KeyPackage for {member_name}, skipping")
            continue
        
        member_kp = KeyPackage.deserialize(bytearray(member_kp_bytes))
        member_leaf = member_kp.content.leaf_node
        
        # Add leaf to tree (simulate add_member without Welcome)
        #new_leaf_index = len(tree.leaves)
        
        # Extend tree if needed
        while tree.nodes <= leaf_index:
            tree.extend()
        
        # Add the leaf
        tree[leaf_index] = member_leaf
        tree[leaf_index]._leaf_index = leaf_index
        
        # Update indices
        for i in range(len(tree.leaves)):
            if isinstance(tree.leaves[i], LeafNode):
                tree.leaves[i]._leaf_index = i
        
        tree.update_leaf_index()
        tree.update_node_index()
        
        epoch += 1
        print(f"      Tree now has {len(tree.leaves)} leaves, epoch {epoch}")
    
    # 5. Get current epoch from group details
    group_details = get_group_details(group_id_b64, token)
    current_epoch = group_details.get('last_epoch', epoch)
    
    print(f"   Final tree: {len(tree.leaves)} leaves, {tree.nodes} nodes")
    print(f"   Current epoch: {current_epoch}")
    
    return tree, current_epoch, members

def get_batch_latest_keypackages(user_ids: List[str], token: str = None) -> dict:
    """Get latest key packages for multiple users in one GET request"""
    try:
        # Join user_ids with commas for query parameter
        user_ids_param = ",".join(user_ids)
        
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        response = requests.get(
            f"{BASE_URL}/key_packages/batch?user_ids={user_ids_param}",
            headers=headers
        )
        
        print(f"📦 Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"❌ Batch request failed: {response.text}")
            return {}
            
        data = response.json()
        
        # Decode base64 key packages back to bytes
        result = {}
        for user_id, kp_data in data.get("key_packages", {}).items():
            if kp_data:
                result[user_id] = {
                    "key_package": base64.b64decode(kp_data["key_package"]),
                    "ref_hash": kp_data["ref_hash"]
                }
            else:
                result[user_id] = None
        return result
    except Exception as e:
        print(f"❌ Batch get keypackages failed: {e}")
        return {}


def add_group_members_batch(group_id_b64: str, members: List[dict], token: str) -> bool:
    """Add multiple members to a group in one request"""
    try:
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        response = requests.post(
            f"{BASE_URL}/groups/{group_id_hex}/members/batch",
            json={"members": members},
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Batch add members failed: {e}")
        return False

def insert_welcome_batch(group_id_b64: str, welcomes: List[dict], token: str) -> bool:
    """Store multiple welcome messages in one request"""
    try:
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        response = requests.post(
            f"{BASE_URL}/groups/{group_id_hex}/welcome/batch",
            json={"welcomes": welcomes},
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        print(f"✅ Batch stored {len(welcomes)} welcomes")
        return True
    except Exception as e:
        print(f"❌ Batch store welcomes failed: {e}")
        return False