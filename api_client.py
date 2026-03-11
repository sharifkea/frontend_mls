# api_client.py
import requests
import base64
import hashlib

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
    """Get all groups for the current user"""
    try:
        response = requests.get(
            f"{BASE_URL}/users/me/groups",
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Get my groups failed: {str(e)}")
        return {"error": str(e)}

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

def save_epoch_secret(group_id: str, epoch: int, epoch_secret: bytes, token: str):
    """Save epoch secret to database"""
    try:
        import base64
        secret_b64 = base64.b64encode(epoch_secret).decode('ascii')
        
        # Try the dedicated endpoint first
        response = requests.post(
            f"{BASE_URL}/groups/{group_id}/epoch-secret",
            json={"epoch": epoch, "epoch_secret": secret_b64},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        
        if response.status_code == 200:
            print(f"✅ Saved epoch secret for group {group_id}")
            return response.json()
        else:
            # Fallback to epoch update endpoint
            response = requests.post(
                f"{BASE_URL}/groups/{group_id}/epoch?new_epoch={epoch}",
                json={"epoch_secret": secret_b64},
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}"
                }
            )
            response.raise_for_status()
            print(f"✅ Saved epoch secret via epoch update")
            return response.json()
            
    except Exception as e:
        print(f"❌ Failed to save epoch secret: {str(e)}")
        return {"error": str(e)}
    
def get_group_members(group_id_b64: str, token: str):
    """Get group members - convert base64 to hex"""
    try:
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        response = requests.get(
            f"{BASE_URL}/groups/{group_id_hex}/members",
            headers={"Authorization": f"Bearer {token}"}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Failed to get group members: {str(e)}")
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
    
def save_epoch_secret_in_db(group_id: str, new_epoch: int, token: str, epoch_secret: bytes = None):
    print(f"\n=== Updating group {group_id} to epoch {new_epoch} ===")

    url = f"{BASE_URL}/groups/{group_id}/epoch"
    payload = {"new_epoch": new_epoch}

    if epoch_secret:
        import base64
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

def save_epoch_secret_direct(group_id_b64: str, epoch: int, epoch_secret: bytes, token: str):
    """Save epoch secret to FastAPI backend"""
    try:
        import base64
        import requests
        
        print(f"\n🔍 SAVE EPOCH SECRET DEBUG:")
        print(f"  - group_id_b64: {group_id_b64}")
        print(f"  - epoch: {epoch}")
        print(f"  - epoch_secret length: {len(epoch_secret)} bytes")
        
        # Convert base64 group_id to hex
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()
        
        # Convert epoch_secret to base64 for JSON
        secret_b64 = base64.b64encode(epoch_secret).decode('ascii')
        
        # Try the epoch update endpoint
        url = f"{BASE_URL}/groups/{group_id_hex}/epoch?new_epoch={epoch}"
        payload = {"epoch_secret": secret_b64}
        
        print(f"  - URL: {url}")
        print(f"  - Payload: {payload}")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        
        response = requests.post(url, json=payload, headers=headers)
        print(f"  - Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"  - Response: {result}")
            print(f"✅ Epoch secret saved")
            return result
        else:
            print(f"❌ Error: {response.text}")
            return {"error": f"HTTP {response.status_code}: {response.text}"}
            
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
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

def update_group_epoch(group_id: str, new_epoch: int, token: str, epoch_secret: bytes = None):
    print(f"\n=== Updating group {group_id} to epoch {new_epoch} ===")

    url = f"{BASE_URL}/groups/{group_id}/epoch"
    payload = {"new_epoch": new_epoch}

    if epoch_secret:
        import base64
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
 

def get_group_members(group_id_b64: str, token: str):
    """Get group members - using hex in URL"""
    print(f"\n=== Getting members for group {group_id_b64} ===")
    
    try:
        import base64
        import requests
        
        # Convert base64 to hex for URL
        group_id_bytes = base64.b64decode(group_id_b64)
        group_id_hex = group_id_bytes.hex()

        url = f"{BASE_URL}/groups/{group_id_b64}/members"
        
        #url = f"{BASE_URL}/groups/{group_id_hex}/members"
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
    
def debug_print(step, data):
    """Simple debug function"""
    print(f"\n🔍 DEBUG [{step}]: {data}")