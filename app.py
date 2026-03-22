# app.py
import uuid, os, time, sys, json, base64, api_client, create_keypakage

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from cryptography.fernet import Fernet




sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.Enums._cipher_suite import CipherSuite
from mls_stuff.MLS import MLSMessage
from mls_stuff.Enums import  WireFormat
from mls_stuff.RatchetTree import RatchetTree, RatchetNode, LeafNode
from mls_stuff.Enums import ExtensionType

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 
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
    group = api_client.create_empty_group(leaf_node, username)
    
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
        private_key, init_priv, key_package_bytes = create_keypakage.GeneratKeyPackage(username)
        
        # 3. Upload key package to backend database
        print(f"Uploading new key package (old ones will be deactivated)...")
        upload_result = api_client.upload_keypackage(user_id, key_package_bytes)
        # Deserialize to get the proper MLS reference hash
        

        # Compute reference hash (same as in MLS)
        key_package = KeyPackage.deserialize(bytearray(key_package_bytes))
        ref_hash_hex = key_package.reference_hash(cs).hex() 
        print(f"✅ Key package uploaded. Reference hash: {ref_hash_hex[:16]}...")
        
        # Store with reference
        if user_id not in user_crypto_store:
            user_crypto_store[user_id] = {'keys': {}}
        
        # 4. Store in server memory
        if user_id not in user_crypto_store:
            user_crypto_store[user_id] = {}
        
        user_crypto_store[user_id]['keys'][ref_hash_hex] = {
            'private_key': private_key,
            'init_priv': init_priv,
            'created_at': time.time()
        }
        user_crypto_store[user_id]['private_key'] = private_key
        user_crypto_store[user_id]['username'] = username
        user_crypto_store[user_id]['key_package'] = base64.b64encode(key_package_bytes).decode('ascii')
        user_crypto_store[user_id]['login_time'] = time.time()
        user_crypto_store[user_id]['current_key'] = ref_hash_hex
        
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
    
    try:        
        # STEP 2: Get creator's key package
        print("\n--- STEP 2: Getting creator's key package from DB ---")
        creator_kp_bytes = api_client.get_latest_keypackage(creator_id)
        if not creator_kp_bytes:
            error_msg = f"No key package found for creator {creator_username}. Please login again."
            print(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        print(f"✅ Got creator key package: {len(creator_kp_bytes)} bytes")
        
        # Get creator's private key
        if creator_id not in user_crypto_store or 'private_key' not in user_crypto_store[creator_id]:
            error_msg = f"Private key not found for creator {creator_username}. Please login again."
            print(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        creator_private_key = user_crypto_store[creator_id]['private_key']
        print(f"✅ Got creator private key from crypto store")
        
        # STEP 3: Create empty group
        print("\n--- STEP 3: Creating empty group ---")
        creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes))
        creator_leaf = creator_kp.content.leaf_node
        group = api_client.create_empty_group(creator_leaf, creator_username)

        

        
        group_id_bytes = group['group_id'].data
        group_id_b64 = base64.b64encode(group_id_bytes).decode('ascii')
        group_id_hex = group_id_bytes.hex()
        
        print(f"✅ Group created successfully!")
        print(f"  - Group ID (b64): {group_id_b64}")
        print(f"  - Group ID (hex): {group_id_hex}")
        print(f"  - Initial Epoch: {group['epoch']}")

        # ===== ADD THIS: Save tree for creator =====
        tree = group['tree']  # Get the ratchet tree from the group

        # Serialize tree for storage
        tree_serialized = tree.serialize()
        tree_b64 = base64.b64encode(tree_serialized).decode('ascii')

        # Save group state with tree for creator
        #if 'groups' not in user_crypto_store[creator_id]:
        #    user_crypto_store[creator_id]['groups'] = {}

        #user_crypto_store[creator_id]['groups'][group_id_b64] = {
        #    'epoch_secret': base64.b64encode(group['epoch_secret']).decode('ascii'),
        #    'init_secret': base64.b64encode(group['init_secret']).decode('ascii'),
        #    'epoch': group['epoch'],
        #    'tree_serialized': tree_b64,  # ← ADD THIS!
        #    'group_id_b64': group['group_id_b64'],
        #    'my_leaf_index': 0,  # Creator is always leaf 0
        #    'member_count': 1  # Initially just creator
        #}
        #print(f"✅ Group tree saved to crypto store for creator (leaf index 0)")

        # STEP 4: Save group to database
        print("\n--- STEP 4: Saving group to database ---")
        create_response = api_client.create_group_with_id(
            group_name, 1, token, group_id_b64
        )
        if 'error' in create_response:
            print(f"❌ Failed to save group: {create_response['error']}")
            return jsonify({'error': f"Failed to save group: {create_response['error']}"}), 500
        print(f"✅ Group saved to database with ID: {group_id_b64}")

        # STEP 5: Add creator to group_members
        print("\n--- STEP 5: Adding creator to group_members ---")
        member_result = api_client.add_group_member(group_id_b64, creator_id, 0, token)
        if 'error' in member_result:
            print(f"⚠️ Failed to add creator to database: {member_result['error']}")
        else:
            print(f"✅ Creator added to group_members at leaf index 0")

        # STEP 6: Store initial epoch secret (NOW creator is a member)
        print("\n--- STEP 6: Storing initial epoch secret (epoch 0) ---")
        if api_client.store_epoch_secret(
            group_id_b64=group_id_b64,
            epoch=0,  # Initial epoch
            epoch_secret=group['epoch_secret'],
            token=token
        ):
            print(f"✅ Initial epoch secret stored in database")
        else:
            print(f"❌ Failed to store initial epoch secret")

        # STEP 7: Store group state in crypto store for creator
        if 'groups' not in user_crypto_store[creator_id]:
            user_crypto_store[creator_id]['groups'] = {}
        
        # saving group data at the enhanced storage:
        user_crypto_store[creator_id]['groups'][group_id_b64] = {
            'epoch_secret': base64.b64encode(group['epoch_secret']).decode('ascii'),
            'init_secret': base64.b64encode(group['init_secret']).decode('ascii'),
            'epoch': group['epoch'],
            'tree_serialized': tree_b64,
            'group_id_b64': group['group_id_b64'],
            'my_leaf_index': 0,
            'member_count': 1
        }
        print(f"✅ Group tree saved to crypto store for creator (leaf index 0)")
        
        # STEP 8: Add each online user to the group
        print("\n--- STEP 8: Adding online users to group ---")
        leaf_index = 1
        added_members = [creator_username]
        
        for user in online_users:
            user_id = user.get('user_id')
            username = user.get('username')
            
            print(f"\n📌 Adding user: {username} ({user_id})")
            
            # Get user's key package
            user_kp_bytes = api_client.get_latest_keypackage(user_id)
            if not user_kp_bytes:
                print(f"⚠️ No key package for {username}, skipping")
                continue
            
            print(f"  - Got user key package: {len(user_kp_bytes)} bytes")
            
            # Add to group (MLS operation) - THIS INCREMENTS THE EPOCH
            welcome = api_client.add_member(group, user_id, creator_private_key)
            current_epoch = group['epoch']  # Get the new epoch after adding
            print(f"  - MLS add_member completed, new epoch: {current_epoch}")
            
            # Store welcome message
            if welcome:
                # Wrap the Welcome in an MLSMessage first
                welcome_message = MLSMessage(
                    wire_format=WireFormat.MLS_WELCOME,  # ← Use WELCOME format, not PUBLIC_MESSAGE!
                    msg_content=welcome
                )
                
                welcome_bytes = welcome_message.serialize()
                resp = api_client.insert_welcome(
                    group_id_b64=group_id_b64,
                    new_member_id=user_id,
                    welcome_bytes=welcome_bytes,
                    token=token
                )
                print(f"  - Welcome delivery status: {resp.get('status', 'unknown')}")
            
            # Add to database group_members
            member_result = api_client.add_group_member(
                group_id_b64, user_id, leaf_index, token
            )
            if 'error' in member_result:
                print(f"⚠️ Failed to add to database: {member_result['error']}")
            else:
                print(f"  - Added to group_members at leaf index {leaf_index}")
                added_members.append(username)
            
            # After add_member, verify epoch incremented
            old_epoch = current_epoch - 1
            print(f"  - Epoch incremented from {old_epoch} to {current_epoch}")
            
            # Store the NEW epoch secret for this epoch
            if api_client.store_epoch_secret(
                group_id_b64=group_id_b64,
                epoch=current_epoch,  # Use the current epoch after adding
                epoch_secret=group['epoch_secret'],
                token=token
            ):
                print(f"  - ✅ Epoch secret for epoch {current_epoch} stored")
            else:
                print(f"  - ❌ Failed to store epoch secret for epoch {current_epoch}")
            
            # After add_member, the tree has been updated
            # Get the updated tree
            updated_tree = group['tree']
            updated_tree_serialized = updated_tree.serialize()
            updated_tree_b64 = base64.b64encode(updated_tree_serialized).decode('ascii')

            # Get the updated tree
            updated_tree = group['tree']
            updated_tree_serialized = updated_tree.serialize()
            updated_tree_b64 = base64.b64encode(updated_tree_serialized).decode('ascii')
            
            # Update creator's stored tree
            user_crypto_store[creator_id]['groups'][group_id_b64]['tree_serialized'] = updated_tree_b64
            user_crypto_store[creator_id]['groups'][group_id_b64]['epoch'] = group['epoch']
            user_crypto_store[creator_id]['groups'][group_id_b64]['member_count'] = len(group['members'])
            
            print(f"   - Updated creator's tree after adding {username}")
            
            leaf_index += 1
        
        # STEP 9: Final epoch update (to ensure group's last_epoch is current)
        print("\n--- STEP 9: Final group epoch update ---")
        if api_client.update_group_epoch(
            group_id_b64,
            group['epoch'],  # Final epoch after all additions
            token,
            group['epoch_secret']
        ):
            print(f"✅ Group epoch updated to {group['epoch']} in database")
        else:
            print(f"⚠️ Failed to update final epoch")

        # STEP 10: Final verification
        print("\n--- STEP 10: Verifying database entries ---")
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
        
        welcomes= welcomes_data.get('welcomes', [])
        
        for welcome in welcomes:
            print("------------------------------")
            print(f"Welcome ID:{welcome.get("id")}")
            print("------------------------------")

        return jsonify({
            'success': True,
            'welcomes': welcomes
        })
        
    except Exception as e:
        print(f"❌ Error fetching pending welcomes: {str(e)}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/welcomes/process', methods=['POST'])
def process_welcome():
    """Process a welcome message and join a group"""
    print("\n" + "="*60)
    print("PROCESS WELCOME ENDPOINT CALLED")
    print("="*60)
    
    # DEBUG: Check global user_crypto_store
    print(f"🔍 Global user_crypto_store: {user_crypto_store}")
    print(f"🔍 Global user_crypto_store type: {type(user_crypto_store)}")
    print(f"🔍 Global user_crypto_store keys: {list(user_crypto_store.keys()) if user_crypto_store else 'Empty'}")
    
    data = request.json
    print(f"📦 Request data: {data}")
    
    welcome_b64 = data.get('welcome_b64')
    group_id_b64 = data.get('group_id')
    welcome_id = data.get('welcome_id')
    
    if not welcome_id:
        return jsonify({'error': 'Missing welcome_id. Cannot process.'}), 400
    
    print(f"📦 Extracted - welcome_b64 length: {len(welcome_b64) if welcome_b64 else 0}")
    print(f"📦 Extracted - group_id_b64: {group_id_b64}")
    print("------------------------------")
    print(f"Welcome ID:{welcome_id}")
    print("------------------------------")

    
    if not welcome_b64 or not group_id_b64 :
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Get user info from session
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"👤 Session user_id: {user_id}")
    print(f"👤 Session username: {username}")
    
    if not user_id or not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # DEBUG: Check user_crypto_store for this user
    print(f"🔍 user_id in user_crypto_store? {user_id in user_crypto_store}")
    
    if user_id in user_crypto_store:
        print(f"🔍 user_crypto_store[user_id] keys: {list(user_crypto_store[user_id].keys())}")
        
        if 'keys' in user_crypto_store[user_id]:
            print(f"🔍 Available key refs: {list(user_crypto_store[user_id]['keys'].keys())}")
        
        # 1. Decode welcome
        welcome_bytes = base64.b64decode(welcome_b64)
        #welcome = Welcome.deserialize(bytearray(welcome_bytes))
        welcome_bytearray = bytearray(welcome_bytes)

        print(f"Received bytes first 16: {bytes(welcome_bytearray[:16]).hex()}   (len={len(welcome_bytes)})")

        try:
            # Step 1: Try to parse as MLSMessage (most likely case)
            mls_msg = MLSMessage.deserialize(welcome_bytearray)
            
            print(f"Parsed as MLSMessage, wire_format={mls_msg.wire_format}")
            
            if hasattr(mls_msg, 'msg_content') and isinstance(mls_msg.msg_content, Welcome):
                welcome = mls_msg.msg_content
                print("→ Extracted Welcome from MLSMessage")
            else:
                print("→ MLSMessage content is not a Welcome → fallback")
                raise ValueError("Not a Welcome inside MLSMessage")
                
        except Exception as e:
            print(f"MLSMessage parse failed: {str(e)} → trying direct Welcome")
            try:
                welcome = Welcome.deserialize(welcome_bytearray)
                print("→ Parsed directly as Welcome (unexpected)")
            except Exception as e2:
                return {"error": f"Cannot parse welcome: {str(e)} | {str(e2)}"}
            
        print(f"  Welcome deserialized ({len(welcome_bytes)} bytes, {len(welcome.secrets)} secrets)")
        
        if not welcome.secrets:
            print("❌ No secrets found in welcome message")
            return {"error": "No secrets in welcome"}
        
        # 2. Get the first encrypted secret
        encrypted_secret = welcome.secrets[0]
        print("  First encrypted secret details:")
        
        # 3. Extract the key package reference from the secret
        key_package_ref = encrypted_secret.new_member.to_bytes().hex()
            
        if key_package_ref in user_crypto_store[user_id]['keys']:
            print(f"✅ Key found for ref {key_package_ref[:16]}...")
            private_key = user_crypto_store[user_id]['keys'][key_package_ref]['init_priv']
            print(f"✅ Private key length: {len(private_key)}")
        else:
            print(f"❌ Key {key_package_ref[:16]}... NOT FOUND in stored keys")
        
    else:
        print(f"❌ User {user_id} not found in user_crypto_store")
 
    token = session.get('token')
    user_id = session.get('user_id')
    username = session.get('username')
    print(f"User {username} ({user_id}) is processing welcome for group {group_id_b64}")
    print(f"Welcome message size: {len(welcome_b64) if welcome_b64 else 'N/A'} bytes")
    
    if not user_id or not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Call the processing function and PASS the private key
        result = api_client.process_single_welcome(
            private_key=private_key,  # ← Pass the stored key!
            welcome_b64=welcome_b64,
            group_id_b64=group_id_b64
        )
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400

        # Now we have crypto success → enrich with tree info
        group_state = result['group_state_crypto']
        group_info = result['group_info']

         # 2. Get additional group details (including last_epoch from database)
        # Call FastAPI's /groups/{group_id} endpoint to get full group details
        group_details = api_client.get_group_details(group_id_b64, token)
        
        if 'error' in group_details:
            return jsonify({'error': 'Failed to fetch Group Detailss'}), 500
            
        # ────────────────────────────────────────────────
        # 3. Fetch group members to get MY leaf index
        # ────────────────────────────────────────────────
        members_data = api_client.get_group_members(group_id_b64, token)
        if 'error' in members_data:
            return jsonify({'error': f"Cannot fetch members: {members_data['error']}"}), 500

        members = members_data.get('members', [])

        if not members:
            return jsonify({'error': 'Group has no members (impossible)'}), 500
        
        # Get the count
        member_count = len(members)

        # Find your own leaf index
        my_leaf_index = None
        for member in members:
            if member.get('user_id') == user_id:
                my_leaf_index = member.get('leaf_index')
                break

        if my_leaf_index is None:
            return jsonify({'error': 'Your user_id not found in group members'}), 500

        print(f"   My leaf index = {my_leaf_index}")
        
        group_state['group_last_epoch'] = group_details.get('last_epoch')
        group_state['member_count'] = member_count
        group_state['my_leaf_index'] = my_leaf_index

        # Reconstruct / load ratchet tree (prefer extension, fallback to DB)
        # ────────────────────────────────────────────────
        tree = None

        # First: try to get tree from GroupInfo extension (most accurate)
        if hasattr(group_info, 'extensions') and group_info.extensions:
            for ext in group_info.extensions:
                if ext.extension_type == ExtensionType.ratchet_tree:
                    tree_data = bytes(ext.extension_data.data)
                    try:
                        tree = RatchetTree.deserialize(bytearray(tree_data))
                        print(f"✅ Ratchet tree loaded from GroupInfo extension ({len(tree_data)} bytes)")
                        break
                    except Exception as e:
                        print(f"⚠️ Failed to deserialize ratchet_tree extension: {e}")

        # Fallback: build minimal tree from known members & my position
        if tree is None:
            print("   No usable ratchet_tree extension → building from group members")
            
            # We already have members_data and my_leaf_index from earlier
            max_leaf = max((m.get('leaf_index', 0) for m in members), default=0)
            required_leaves = max(len(members), my_leaf_index + 1)

            tree = RatchetTree()
            tree.root = RatchetNode()  # must have root

            # Extend until large enough
            while len(tree.leaves) < required_leaves:
                tree.extend()

            # Mark your own leaf (placeholder)
            if my_leaf_index < len(tree.leaves):
                tree[my_leaf_index] = RatchetNode()  # or minimal LeafNode

            print(f"   Built fallback tree: {len(tree.leaves)} leaves, your index: {my_leaf_index}")

            pass
        
        # For each member, fetch their key package and extract leaf node
        for member in members:
            member_user_id = member['user_id']  # NOT user_id
            leaf_index = member['leaf_index']
            
            kp_bytes = api_client.get_latest_keypackage(member_user_id)
            if kp_bytes:
                key_package = KeyPackage.deserialize(bytearray(kp_bytes))
                leaf_node = key_package.content.leaf_node
                tree[leaf_index] = leaf_node
                print(f"  Added leaf {leaf_index} for {member['username']}")

        # Serialize tree for storage
        tree_serialized = tree.serialize()
        tree_b64 = base64.b64encode(tree_serialized).decode('ascii')

        # Add to group_state
        group_state['tree'] = tree
        group_state['tree_serialized'] = tree_b64
        group_state['my_leaf_index'] = my_leaf_index
        group_state['member_count'] = member_count
        # Optional: store serialized version if you ever want persistence
        # group_state['tree_serialized'] = base64.b64encode(tree.serialize()).decode('ascii')

        # ────────────────────────────────────────────────
        # Final storage
        # ────────────────────────────────────────────────
        if user_id not in user_crypto_store:
            user_crypto_store[user_id] = {}
        if 'groups' not in user_crypto_store[user_id]:
            user_crypto_store[user_id]['groups'] = {}

        user_crypto_store[user_id]['groups'][group_id_b64] = group_state
        print(f"--------------------{welcome_id}")
        response=api_client.mark_welcome_delivered(welcome_id, token)
        # 1. Check if the 'status' key exists
        if response.get("status") == "delivered":
            print(f"Welcome delivered set True")
        else:
            # 2. If it's not 'delivered', raise an error manually
            # This catches {"status": "error"} or even empty responses
            actual_status = response.get("status", "Unknown Error")
            raise ValueError(f"API failed to deliver. Expected 'delivered', got: {actual_status}")
        
        return jsonify({
            'success': True,
            'group_id': group_id_b64,
            'epoch': group_state['epoch'],
            'my_leaf_index': my_leaf_index,
            'message': 'Successfully joined group with tree'
        })
        
    except Exception as e:
        print(f"❌ Error processing welcome: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
def restore_group_tree(user_id, group_id_b64):
    """Restore group tree from stored state"""
    if user_id not in user_crypto_store:
        return None
    
    groups = user_crypto_store[user_id].get('groups', {})
    group_state = groups.get(group_id_b64, {})
    tree_b64 = group_state.get('tree_serialized')
    
    if tree_b64:
        try:
            tree_bytes = base64.b64decode(tree_b64)
            tree = RatchetTree.deserialize(bytearray(tree_bytes))
            print(f"✅ Tree restored for group {group_id_b64}")
            return tree
        except Exception as e:
            print(f"⚠️ Failed to restore tree: {e}")
    
    return None

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