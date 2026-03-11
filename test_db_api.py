# test_db_api.py
# Tests FastAPI + PostgreSQL connection and KeyPackage operations
# Run this after uvicorn main:app is running on http://localhost:8000

import requests
import os
import hashlib
from uuid import uuid4
import binascii
from create_keypakage import GeneratKeyPackage
BASE_URL = "http://localhost:8000"

# Test files – replace with your real KeyPackage files
# or just use dummy data for testing
DUMMY_KEYPACKAGE = b"MLS-TEST-KEYPACKAGE-DATA-285BYTES-" + os.urandom(200)  # ~285 bytes dummy


def test_db_connection():
    print("\n=== 1. Testing database connection ===")
    try:
        r = requests.get(f"{BASE_URL}/test-db")
        r.raise_for_status()
        print("SUCCESS: Database connected")
        print("Response:", r.json())
    except Exception as e:
        print("FAILED:", str(e))


def test_user_registration(user_name: str, password: str):
    print(f"\n=== 2. Registering user {user_name} ===")
    try:
        r = requests.post(
            f"{BASE_URL}/users", 
            json={"username": user_name, "password": password},
            headers={"Content-Type": "application/json"}
        )
        r.raise_for_status()
        print("SUCCESS: User registered")
        print("Response:", r.json())
        return r.json().get("user_id")
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_user_login(user_name: str, password: str):
    print(f"\n=== 3. Logging in user {user_name} ===")
    try:
        r = requests.post(
            f"{BASE_URL}/login",
            data={"username": user_name, "password": password},  # using 'data' not 'json' for form-urlencoded
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        r.raise_for_status()
        print("SUCCESS: User logged in")
        print("Response:", r.json())
        return r.json().get("user_id"), r.json().get("access_token")
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_upload_keypackage(user_id: str, key_package_bytes: bytes):
    print(f"\n=== 4. Uploading KeyPackage for {user_id} ===")
    ref_hash = hashlib.sha256(key_package_bytes).digest()
    print("First 32 bytes (hex):", key_package_bytes[:32].hex())
    try:
        r = requests.post(
            f"{BASE_URL}/key_packages/{user_id}",
            data=key_package_bytes,
            headers={"Content-Type": "application/octet-stream"}
        )
        r.raise_for_status()
        print("SUCCESS: Uploaded")
        print("Response:", r.json())
        return r.json().get("ref_hash"),r.json().get("key_package_id")
    except Exception as e:
        print("FAILED:", str(e))
        return None


def test_get_latest_keypackage(user_id: str):
    print(f"\n=== 5. Fetching latest unused KeyPackage for {user_id} ===")
    try:
        r = requests.get(f"{BASE_URL}/key_packages/{user_id}/latest")
        r.raise_for_status()
        print("SUCCESS: Fetched")
        print(f"Size: {len(r.content)} bytes")
        print(f"Content-Type: {r.headers.get('content-type')}")
        return r.content
    except Exception as e:
        print("FAILED:", str(e))
        return None


def test_mark_used(ref_hash_hex: str):
    print(f"\n=== 6. Marking KeyPackage as used (ref_hash: {ref_hash_hex}) ===")
    try:
        r = requests.post(
            f"{BASE_URL}/key_packages/mark-used",
            json={"ref_hash": ref_hash_hex},
            headers={"Content-Type": "application/json"}
        )
        r.raise_for_status()
        print("SUCCESS:", r.json())
    except Exception as e:
        print("FAILED:", str(e))


def test_cleanup():
    print("\n=== 5. Running cleanup (expired/used packages) ===")
    try:
        r = requests.post(f"{BASE_URL}/cleanup")
        r.raise_for_status()
        print("SUCCESS:", r.json())
    except Exception as e:
        print("FAILED:", str(e))


def test_delete_user(user_id: str, token: str):
    print(f"\n=== Deleting user {user_id} ===")
    try:
        r = requests.delete(
            f"{BASE_URL}/users/{user_id}",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
        r.raise_for_status()
        print("SUCCESS: User deleted")
        if r.text:  # Check if there's a response body
            print("Response:", r.json())
        else:
            print("User deleted successfully (no response body)")
        return True
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return False
    

def test_new_mark_used(ref_hash_hex: str):
    print(f"\n=== 6. Marking KeyPackage as used (ref_hash: {ref_hash_hex}) ===")
    
    # Clean the ref_hash - remove 0x prefix if present
    if ref_hash_hex.startswith('0x'):
        ref_hash_hex = ref_hash_hex[2:]
        print(f"Cleaned ref_hash: {ref_hash_hex}")
    
    try:
        r = requests.post(
            f"{BASE_URL}/key_packages/new-mark-used",
            json={"ref_hash": ref_hash_hex},
            headers={"Content-Type": "application/json"}
        )
        print(f"Response status: {r.status_code}")
        print(f"Response body: {r.text}")
        r.raise_for_status()
        print("SUCCESS:", r.json())
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error response: {e.response.text}")

# Add these new functions to test_db_api.py

def test_create_group_with_id(group_name: str, cipher_suite: int, token: str, group_id:bytes):
    """Create a new MLS group"""
    print(f"\n=== Creating group: {group_name} ===")
    try:
        r = requests.post(
            f"{BASE_URL}/groups",
            json={"group_name": group_name, "cipher_suite": cipher_suite, "group_id": group_id},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        r.raise_for_status()
        print("SUCCESS: Group created")
        print("Response:", r.json())
        return r.json().get("group_id")
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_add_group_member(group_id: str, user_id: str, leaf_index: int, token: str):
    """Add a member to a group"""
    print(f"\n=== Adding member {user_id} to group {group_id} ===")
    try:
        r = requests.post(
            f"{BASE_URL}/groups/{group_id}/members",
            json={"user_id": user_id, "leaf_index": leaf_index},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        r.raise_for_status()
        print("SUCCESS: Member added")
        print("Response:", r.json())
        return True
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return False

def test_send_message(group_id: str, ciphertext: bytes, nonce: bytes, epoch: int, 
                     content_type: int, token: str, wire_format: int = 1):
    """Store an encrypted message"""
    print(f"\n=== Storing message for group {group_id} ===")
    
    # Encode binary data as base64
    import base64
    ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
    nonce_b64 = base64.b64encode(nonce).decode('ascii')
    
    payload = {
        "group_id": group_id,
        "ciphertext": ciphertext_b64,
        "nonce": nonce_b64,
        "epoch": epoch,
        "content_type": content_type,
        "wire_format": wire_format
    }
    
    try:
        r = requests.post(
            f"{BASE_URL}/messages",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        r.raise_for_status()
        print("SUCCESS: Message stored")
        print("Response:", r.json())
        return r.json().get("message_id")
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_get_group_messages(group_id: str, token: str, since_epoch: int = None, limit: int = 100):
    """Retrieve messages from a group"""
    print(f"\n=== Getting messages from group {group_id} ===")
    
    url = f"{BASE_URL}/groups/{group_id}/messages"
    params = {"limit": limit}
    if since_epoch is not None:
        params["since_epoch"] = since_epoch
    
    try:
        r = requests.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}"}
        )
        r.raise_for_status()
        print("SUCCESS: Messages retrieved")
        response_data = r.json()
        print(f"Found {len(response_data.get('messages', []))} messages")
        return response_data
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_update_group_epoch(group_id: str, new_epoch: int, token: str, epoch_secret: bytes = None):
    """Update group to new epoch - using query parameter"""
    print(f"\n=== Updating group {group_id} to epoch {new_epoch} ===")
    
    # Build URL with query parameter
    url = f"{BASE_URL}/groups/{group_id}/epoch?new_epoch={new_epoch}"
    
    # Prepare optional body for epoch_secret
    payload = {}
    if epoch_secret:
        import base64
        payload["epoch_secret"] = base64.b64encode(epoch_secret).decode('ascii')
    
    try:
        # Use params for query string, json for body
        r = requests.post(
            url,
            json=payload if payload else None,
            headers={"Authorization": f"Bearer {token}"}
        )
        r.raise_for_status()
        print("SUCCESS: Group epoch updated")
        print("Response:", r.json())
        return True
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return False

def test_get_group_details(group_id: str, token: str):
    """Get detailed information about a group"""
    print(f"\n=== Getting details for group {group_id} ===")
    
    try:
        r = requests.get(
            f"{BASE_URL}/groups/{group_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        r.raise_for_status()
        print("SUCCESS: Group details retrieved")
        print("Response:", r.json())
        return r.json()
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_get_my_groups(token: str):
    """Get all groups for current user"""
    print(f"\n=== Getting user's groups ===")
    
    try:
        r = requests.get(
            f"{BASE_URL}/users/me/groups",
            headers={"Authorization": f"Bearer {token}"}
        )
        r.raise_for_status()
        print("SUCCESS: User groups retrieved")
        print("Response:", r.json())
        return r.json()
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None
    
def get_user_by_username(username: str, token: str = None):
    """
    Get user information by username.
    If token is provided, it's used for authentication.
    If no token, attempts without authentication (if endpoint allows).
    """
    print(f"\n=== Looking up user: {username} ===")
    
    url = f"{BASE_URL}/users?username={username}"
    headers = {}
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        r = requests.get(
            url,
            headers=headers
        )
        r.raise_for_status()
        response_data = r.json()
        
        users = response_data.get('users', [])
        if users:
            user = users[0]  # Take the first match
            print(f"✅ Found user: {user['username']} (ID: {user['user_id']})")
            return user
        else:
            print(f"❌ No user found with username: {username}")
            return None
            
    except Exception as e:
        print(f"FAILED: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def get_user_by_id(user_id: str, token: str = None):
    """
    Get user information by user ID.
    """
    print(f"\n=== Looking up user by ID: {user_id} ===")
    
    url = f"{BASE_URL}/users/{user_id}"
    headers = {}
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        r = requests.get(
            url,
            headers=headers
        )
        r.raise_for_status()
        user_data = r.json()
        print(f"✅ Found user: {user_data['username']}")
        return user_data
        
    except Exception as e:
        print(f"FAILED: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def search_users(search_term: str, token: str = None):
    """
    Search for users by username (partial matches).
    """
    print(f"\n=== Searching for users matching: {search_term} ===")
    
    url = f"{BASE_URL}/users?search={search_term}"
    headers = {}
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        r = requests.get(
            url,
            headers=headers
        )
        r.raise_for_status()
        response_data = r.json()
        
        users = response_data.get('users', [])
        print(f"✅ Found {len(users)} matching users")
        for user in users:
            print(f"   - {user['username']} (ID: {user['user_id']})")
        return users
        
    except Exception as e:
        print(f"FAILED: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return []
        
if __name__ == "__main__":
    print("=== Database & API Integration Test ===\n")
    print("Make sure:")
    print("- uvicorn main:app --reload is running")
    print("- PostgreSQL is on, database 'mls_db' exists")
    print("- Tables & functions created\n")

    test_db_connection()
    test_user = "alice"
    user_id = test_user_registration(test_user,"1234")
    if user_id:
        user_id, token = test_user_login(test_user,"1234")
        if user_id and token:
            user_privet, kp_user=GeneratKeyPackage(test_user)
            ref_hash, key_package_id = test_upload_keypackage(user_id, kp_user)
            if ref_hash:
                latest_kp = test_get_latest_keypackage(user_id)
                if latest_kp:
                    test_mark_used(ref_hash)
                    test_cleanup()
                    bool_ret=test_delete_user(user_id, token)
    
