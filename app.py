# app.py
import uuid

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import os
from dotenv import load_dotenv
import api_client
from cryptography.fernet import Fernet
import base64
import json
import sys
import time

from create_keypakage import GeneratKeyPackage
from api_client import create_empty_group, add_member


sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._welcome import Welcome

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)  # Enable CORS for development

# Store user sessions with their crypto material
# In production, use a proper database
user_crypto_store = {} 

# Track active sessions (users currently logged in)
active_sessions = {}  # user_id -> timestamp

# Encryption for session data (optional but recommended)
cipher = Fernet(Fernet.generate_key())


@app.route('/api/crypto/create-empty-group', methods=['POST'])
def create_empty_group_endpoint():
    """Create an empty group (server-side crypto)"""
    data = request.json
    username = data.get('username')
    key_package_b64 = data.get('key_package')
    
    # Decode key package
    key_package_bytes = base64.b64decode(key_package_b64)
    key_package = KeyPackage.deserialize(bytearray(key_package_bytes))
    leaf_node = key_package.content.leaf_node
    
    # Create group
    group = create_empty_group(leaf_node, username)
    
    # Return group data (public info only)
    return jsonify({
        'success': True,
        'group_id': group['group_id_b64'],
        'epoch': group['epoch'],
        'tree_hash': base64.b64encode(group['group_context'].tree_hash.data).decode('ascii'),
        # Don't send epoch_secret directly - it would be in Welcome message
    })

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    """Handle registration - calls your existing API"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Call your existing API client
    result = api_client.register_user(username, password)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 400
    
    return jsonify({
        'success': True,
        'user_id': result['user_id']
    })

@app.route('/api/login', methods=['POST'])
def login():
    """Handle login - generates fresh key package and uploads to DB"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    print(f"Login attempt for username: {username}")
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    try:
        # 1. Login to get user_id and token
        result = api_client.login_user(username, password)
        print(f"Login result: {result}")
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 401
        
        user_id = result['user_id']
        token = result['access_token']
        
        # 2. Generate FRESH key package for this session
        print(f"Generating fresh key package for {username}...")
        private_key, key_package_bytes = GeneratKeyPackage(username)
        
        # 3. Upload key package to backend database
        print(f"Uploading new key package (old ones will be deactivated)...")
        upload_result = api_client.upload_keypackage(user_id, key_package_bytes)
        
        # 4. Store in server memory
        if user_id not in user_crypto_store:
            user_crypto_store[user_id] = {}
        
        user_crypto_store[user_id]['private_key'] = private_key
        user_crypto_store[user_id]['username'] = username
        user_crypto_store[user_id]['key_package'] = base64.b64encode(key_package_bytes).decode('ascii')
        user_crypto_store[user_id]['login_time'] = time.time()
        
        # 5. IMPORTANT: Add to active_sessions!
        active_sessions[user_id] = {
            'username': username,
            'login_time': time.time()
        }
        print(f"✅ Added {username} to active_sessions. Current active: {list(active_sessions.keys())}")
        
        # 6. Store in session
        session['user_id'] = user_id
        session['token'] = token
        session['username'] = username
        session.permanent = True  # Make session permanent
        
        print(f"Session after login: {dict(session)}")
        print(f"Active sessions now: {len(active_sessions)} users")
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'token': token,
            'username': username,
            'has_key_package': True
        })
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear session and remove from active sessions"""
    user_id = session.get('user_id')
    
    # Remove from active sessions
    if user_id and user_id in active_sessions:
        print(f"Removing {user_id} from active_sessions")
        del active_sessions[user_id]
    
    # Remove PRIVATE key from server memory
    if user_id and user_id in user_crypto_store:
        print(f"Clearing private crypto material for user {user_id}")
        del user_crypto_store[user_id]
    
    session.clear()
    
    print(f"Active sessions after logout: {len(active_sessions)}")
    
    return jsonify({'success': True})

@app.route('/api/active-sessions', methods=['GET'])
def get_active_sessions():
    """Get list of currently active users (for debugging)"""
    return jsonify({
        'active_users': list(active_sessions.keys()),
        'count': len(active_sessions)
    })

@app.route('/api/verify', methods=['GET'])
def verify():
    """Verify token is still valid"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'valid': False}), 401
    
    token = auth_header.split(' ')[1]
    # Here you could verify with your backend if needed
    
    return jsonify({'valid': True})

# Add this function to periodically clean up old sessions
def cleanup_old_sessions():
    """Remove crypto material for users who haven't been active"""
    current_time = time.time()
    expired_users = []
    
    for user_id, data in user_crypto_store.items():
        login_time = data.get('login_time', 0)
        # Remove sessions older than 24 hours
        if current_time - login_time > 24 * 3600:
            expired_users.append(user_id)
    
    for user_id in expired_users:
        print(f"Cleaning up expired session for user {user_id}")
        del user_crypto_store[user_id]

@app.route('/api/online-users', methods=['GET'])
def get_online_users():
    """Get list of currently logged-in users"""
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Return list of online users (excluding current user)
    online_users = [
        {'user_id': uid, 'username': data['username']}
        for uid, data in active_sessions.items()
        if uid != user_id  # Exclude current user
    ]
    
    return jsonify({
        'success': True,
        'users': online_users,
        'count': len(online_users)
    })

@app.route('/api/groups/create-with-online', methods=['POST'])
def create_group_with_online():
    """Create a group with all online users (excluding creator)"""
    data = request.json
    group_name = data.get('group_name', 'MLS Test Group')
    online_users = data.get('users', [])  # List of OTHER online users (excluding creator)
    creator_id = session.get('user_id')
    token = session.get('token')
    creator_username = session.get('username')
    
    print("\n" + "="*60)
    print("CREATE GROUP WITH ONLINE - START")
    print("="*60)
    print(f"Creator: {creator_username} ({creator_id})")
    print(f"Group name: {group_name}")
    print(f"Other online users received: {online_users}")
    print(f"Number of other users: {len(online_users)}")
    
    if not creator_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Can create group even with just the creator (0 other users)
    # But for a group chat, you'd want at least 1 other user
    if len(online_users) < 1:
        print("⚠️ Warning: Creating group with only creator (no other users)")
    
    try:        
        
        # STEP 2: Get creator's key package from database (already generated at login)
        print("\n--- STEP 2: Getting creator's key package from DB ---")
        creator_kp_bytes = api_client.get_latest_keypackage(creator_id)
        if not creator_kp_bytes:
            # This should not happen if key package was generated at login
            error_msg = f"No key package found for creator {creator_username}. Please login again."
            print(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        print(f"✅ Got creator key package: {len(creator_kp_bytes)} bytes")
        
        # Get creator's private key from crypto store (set during login)
        if creator_id not in user_crypto_store or 'private_key' not in user_crypto_store[creator_id]:
            error_msg = f"Private key not found for creator {creator_username}. Please login again."
            print(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        creator_private_key = user_crypto_store[creator_id]['private_key']
        print(f"✅ Got creator private key from crypto store")
        
        # STEP 3: Deserialize creator's key package and create empty group
        print("\n--- STEP 3: Creating empty group ---")
        creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes))
        creator_leaf = creator_kp.content.leaf_node
        
        # Create empty group
        group = create_empty_group(creator_leaf, creator_username)
        
        # Get group ID in various formats
        group_id_bytes = group['group_id'].data
        group_id_b64 = base64.b64encode(group_id_bytes).decode('ascii')
        group_id_hex = group_id_bytes.hex()
        
        print(f"✅ Group created successfully!")
        print(f"  - Group ID (b64): {group_id_b64}")
        print(f"  - Group ID (hex): {group_id_hex}")
        print(f"  - Epoch: {group['epoch']}")
        print(f"  - Epoch secret: {group['epoch_secret'][:16].hex()}...")
        
        # STEP 4: Save group to database
        print("\n--- STEP 4: Saving group to database ---")
        create_response = api_client.create_group_with_id(
            group_name,
            1,  # cipher_suite
            token,
            group_id_b64
        )
        
        if 'error' in create_response:
            print(f"❌ Failed to save group: {create_response['error']}")
            return jsonify({'error': f"Failed to save group: {create_response['error']}"}), 500
        
        print(f"✅ Group saved to database with ID: {group_id_b64}")
        
        # STEP 5: Store group in crypto store for creator
        if 'groups' not in user_crypto_store[creator_id]:
            user_crypto_store[creator_id]['groups'] = {}
        
        user_crypto_store[creator_id]['groups'][group_id_b64] = {
            'epoch_secret': base64.b64encode(group['epoch_secret']).decode('ascii'),
            'init_secret': base64.b64encode(group['init_secret']).decode('ascii'),
            'epoch': group['epoch']
        }
        print(f"✅ Group state stored in crypto store for creator")
                
        # STEP 6: Add each online user to the group
        print("\n--- STEP 6: Adding online users to group ---")
        leaf_index = 1
        added_members = [creator_username]
        
        for user in online_users:
            user_id = user.get('user_id')
            username = user.get('username')
            
            print(f"\n📌 Adding user: {username} ({user_id})")
            
            # Get user's key package from database (generated at their login)
            user_kp_bytes = api_client.get_latest_keypackage(user_id)
            if not user_kp_bytes:
                print(f"⚠️ No key package for {username}, skipping. They need to login first.")
                continue
            
            print(f"  - Got user key package: {len(user_kp_bytes)} bytes")
            
            # Add to group (MLS operation)
            welcome = add_member(group, user_id, creator_private_key)
            if welcome:
                welcome_bytes = welcome.serialize()
                
                resp = api_client.insert_welcome(
                    group_id_b64=group['group_id_b64'],     # original base64
                    new_member_id=user_id,
                    welcome_bytes=welcome_bytes,            # raw bytes
                    token=token
                )
                print("Welcome delivery status:", resp)

            #welcome = add_member(group, user_id, creator_private_key)
            #welcome_bytes = welcome.serialize()
            #the_b64_string = base64.b64encode(welcome_bytes).decode('utf-8')

            # Send to backend to store welcome message for this user
            # resp=api_client.insert_welcome(group_id_b64,new_member_id=user_id, welcome_b64=the_b64_string, token=token)
            #print("Welcome delivery status:", resp.get("status"))

           #welcome = Welcome.deserialize(bytearray(base64.b64decode(welcome_bytes)))
            #print(welcome)
            print(f"  - MLS add_member completed, new epoch: {group['epoch']}")
            
            # Add to database
            member_result = api_client.add_group_member(
                group_id_b64, 
                user_id, 
                leaf_index, 
                token
            )
            
            if 'error' in member_result:
                print(f"⚠️ Failed to add to database: {member_result['error']}")
            else:
                print(f"  - Added to group_members at leaf index {leaf_index}")
                added_members.append(username)
            
            # Store group state for this user if they're in crypto store
            if user_id in user_crypto_store:
                if 'groups' not in user_crypto_store[user_id]:
                    user_crypto_store[user_id]['groups'] = {}
                
                user_crypto_store[user_id]['groups'][group_id_b64] = {
                    'epoch_secret': base64.b64encode(group['epoch_secret']).decode('ascii'),
                    'init_secret': base64.b64encode(group['init_secret']).decode('ascii'),
                    'epoch': group['epoch']
                }
                print(f"  - Group state stored in crypto_store for {username}")
            
            leaf_index += 1
        
        # STEP 7: Update epoch in database
        print("\n--- STEP 7: Updating group epoch in database ---")
        if (api_client.update_group_epoch(
            group_id_b64,
            group['epoch'],
            token,
            group['epoch_secret']
        )):
            print(f"✅ Group epoch updated to {group['epoch']} in database")
           
        else:
            print(f"⚠️ Failed to update epoch: {group['epoch']} in database")
       
        # STEP 8: Final verification
        print("\n--- STEP 8: Verifying database entries ---")
        final_members = api_client.get_group_members(group_id_b64, token)
        
        if 'error' not in final_members:
            member_count = len(final_members.get('members', []))
            print(f"✅ Found {member_count} members in database")
        else:
            print(f"⚠️ Could not verify members: {final_members.get('error')}")
        
        print("\n" + "="*60)
        print(f"✅ GROUP CREATION COMPLETE - {len(added_members)} members")
        print("="*60)
        
        return jsonify({
            'success': True,
            'group_id': group_id_b64,
            'group_name': group_name,
            'member_count': len(added_members),
            'members': added_members
        })
        
    except Exception as e:
        print(f"\n❌ ERROR creating group: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/groups', methods=['GET'])
def get_user_groups():
    """Get all groups for the current user"""
    user_id = session.get('user_id')
    token = session.get('token')
    
    print(f"\n🔍 GET USER GROUPS - User: {user_id}")
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Call your FastAPI backend to get groups
        
        groups_data = api_client.get_my_groups(token)
        
        if 'error' in groups_data:
            return jsonify({'error': groups_data['error']}), 400
        
        # Enhance group data with information from your crypto store
        groups = groups_data.get('groups', [])
        enhanced_groups = []
        
        for group in groups:
            print(f"Group Name: {group.get('group_name')}")
            group_id = group.get('group_id')
            
            # Add crypto info if available in user_crypto_store
            crypto_info = {}
            if user_id in user_crypto_store and 'groups' in user_crypto_store[user_id]:
                if group_id in user_crypto_store[user_id]['groups']:
                    crypto_info = {
                        'has_keys': True,
                        'epoch': user_crypto_store[user_id]['groups'][group_id].get('epoch')
                    }
            
            enhanced_groups.append({
                **group,
                **crypto_info
            })
        
        return jsonify({
            'success': True,
            'groups': enhanced_groups
        })
        
    except Exception as e:
        print(f"❌ Error getting user groups: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/welcomes/pending', methods=['GET'])
def get_pending_welcomes():
    """Get all pending welcome messages for the current user"""
    user_id = session.get('user_id')
    token = session.get('token')
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Call FastAPI to get pending welcomes
        welcomes_data = api_client.get_pending_welcomes(token)
        
        if 'error' in welcomes_data:
            return jsonify({'error': welcomes_data['error']}), 400
        
        return jsonify({
            'success': True,
            'welcomes': welcomes_data.get('welcomes', [])
        })
        
    except Exception as e:
        print(f"❌ Error fetching pending welcomes: {str(e)}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/welcomes/process', methods=['POST'])
def process_welcome():
    """Process a welcome message and join a group"""
    data = request.json
    welcome_b64 = data.get('welcome_b64')
    group_id_b64 = data.get('group_id')
    
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id or not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get the private key from user_crypto_store
    if user_id not in user_crypto_store or 'private_key' not in user_crypto_store[user_id]:
        return jsonify({'error': 'No private key found. Please login again.'}), 400
    
    private_key = user_crypto_store[user_id]['private_key']
    
    try:
        # Call the processing function and PASS the private key
        result = api_client.process_single_welcome(
            private_key=private_key,  # ← Pass the stored key!
            welcome_b64=welcome_b64,
            group_id_b64=group_id_b64,
            token=session.get('token')
        )
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
        
        # Mark welcome as delivered (optional)
        # You might want to call an endpoint to mark it as delivered
        
        return jsonify({
            'success': True,
            'group_id': group_id_b64,
            'message': 'Successfully joined group'
        })
        
    except Exception as e:
        print(f"❌ Error processing welcome: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/active-sessions', methods=['GET'])
def debug_active_sessions():
    """Debug endpoint to check active sessions"""
    user_id = session.get('user_id')
    
    return jsonify({
        'active_sessions': list(active_sessions.keys()),
        'active_users': [active_sessions[uid]['username'] for uid in active_sessions],
        'count': len(active_sessions),
        'your_session': {
            'user_id': user_id,
            'in_active_sessions': user_id in active_sessions if user_id else False
        }
    })

@app.route('/api/debug/group/<group_id>', methods=['GET'])
def debug_group(group_id):
    """Debug endpoint to check group details in database"""
    token = session.get('token')
     # Force lowercase for consistency
    group_id = group_id.lower()
    
    query = "SELECT * FROM groups WHERE encode(group_id, 'hex') = $1"
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get group details
        group_details = api_client.get_group_details(group_id, token)
        
        # Get group members
        members = api_client.get_group_members(group_id, token)
        
        # Get messages
        messages = api_client.get_group_messages(group_id, token)
        
        return jsonify({
            'group_details': group_details,
            'members': members,
            'message_count': len(messages.get('messages', [])) if messages else 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/db-check', methods=['GET'])
def debug_db_check():
    """Check database contents directly"""
    token = session.get('token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get all groups for user
        groups = api_client.get_my_groups(token)
        
        result = {
            'groups_count': len(groups.get('groups', [])) if groups else 0,
            'groups': groups,
            'database_status': 'check your PostgreSQL directly'
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)