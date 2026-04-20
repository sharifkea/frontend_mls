# app.py
import uuid, os, time, sys, json, base64, api_client,api_client_2,api_client_3,create_keypakage,secrets,requests


from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Create Flask app first
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)



sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.Enums._cipher_suite import CipherSuite
from mls_stuff.MLS import MLSMessage
from mls_stuff.Enums import  WireFormat
from mls_stuff.RatchetTree import RatchetTree, RatchetNode, LeafNode
from mls_stuff.Enums import ExtensionType
from mls_stuff.Crypto._derive_secrets import DeriveSecret

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
       #print(f"Login result: {result}")
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 401
        
        user_id = result['user_id']
        token = result['access_token']
        
    
    
        # Check if there's an existing group that this user should join
        groups_response = api_client.get_my_groups(token)
        groups = groups_response.get('groups', [])
        
        for group in groups:
            group_id_b64 = group.get('group_id')
            
            # Check if current user is already in this group
            members_response = api_client.get_group_members(group_id_b64, token)
            members = members_response.get('members', [])
            
            is_member = any(m.get('user_id') == user_id for m in members)
            
            if not is_member:
                # User is not in this group - notify via FastAPI WebSocket
                creator_id = group.get('creator_user_id')
                
                # Call FastAPI endpoint to notify creator
                try:
                    notify_url = f"http://localhost:8000/api/notify-new-user"
                    response =requests.post(notify_url, json={
                        'creator_id': creator_id,
                        'new_user_id': user_id,
                        'new_username': username,
                        'group_id': group_id_b64,
                        'group_name': group.get('group_name')
                    }, timeout=2)
                    print(f"Notification sent: {response.status_code}")
                except Exception as e:
                    print(f"Failed to notify: {e}")
        
        print(f"   - User ID: {user_id}")
        print(f"   - Token: {token}")
        # 2. Generate FRESH key package for this session
        #print(f"Generating fresh key package for {username}...")
        private_key, init_priv, key_package_bytes = create_keypakage.GeneratKeyPackage(username)
        
        # 3. Upload key package to backend database
       #print(f"Uploading new key package (old ones will be deactivated)...")
        upload_result = api_client.upload_keypackage(user_id, key_package_bytes)
        # Deserialize to get the proper MLS reference hash
        

        # Compute reference hash (same as in MLS)
        key_package = KeyPackage.deserialize(bytearray(key_package_bytes))
        ref_hash_hex = key_package.reference_hash(cs).hex() 
       #print(f"✅ Key package uploaded. Reference hash: {ref_hash_hex[:16]}...")
        
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
       #print(f"✅ Added {username} to active_sessions. Current active: {list(active_sessions.keys())}")
        
        # 6. Store in session
        session['user_id'] = user_id
        session['token'] = token
        session['username'] = username
        session.permanent = True  # Make session permanent
        
       #print(f"Session after login: {dict(session)}")
       #print(f"Active sessions now: {len(active_sessions)} users")
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'token': token,
            'username': username,
            'has_key_package': True
        })
        
    except Exception as e:
       #print(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Login failed'}), 500
    
@app.route('/api/groups/update-state', methods=['POST'])
def update_group_state():
    """Existing member updates their group state after a commit"""
    data = request.json
    group_id_b64 = data.get('group_id')
    
    user_id = session.get('user_id')
    token = session.get('token')
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        print(f"\n🔄 Updating group state for user {user_id}")
        
        # Build tree using the working replay method
        tree, current_epoch, members = api_client.build_tree_by_replay(group_id_b64, token)
        
        # Find my leaf index
        my_leaf_index = None
        for member in members:
            if member.get('user_id') == user_id:
                my_leaf_index = member.get('leaf_index')
                break
        
        # Initialize group state with ratchet
        if user_id not in user_crypto_store:
            user_crypto_store[user_id] = {}
        if 'groups' not in user_crypto_store[user_id]:
            user_crypto_store[user_id]['groups'] = {}
        
        # ✅ USE NEW FUNCTION
        user_crypto_store[user_id]['groups'][group_id_b64] = initialize_group_state_with_ratchet(
            group_id_b64=group_id_b64,
            tree=tree,
            cipher_suite=cs,
            my_leaf_index=my_leaf_index,
            current_epoch=current_epoch,
            my_user_id=user_id
        )
        
        print(f"✅ User {user_id} group state updated with ratchet")
        print(f"   Tree has {len(tree.leaves)} leaves, epoch {current_epoch}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error updating group state: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/groups/add-member', methods=['POST'])
def add_member_to_group():
    """Creator adds a new member to an existing group"""
    data = request.json
    group_id_b64 = data.get('group_id')
    new_user_id = data.get('new_user_id')
    new_username = data.get('new_username')
    
    creator_id = session.get('user_id')
    creator_username = session.get('username')
    token = session.get('token')
    
    if not creator_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # 1. Get current group state from creator's crypto store
        if creator_id not in user_crypto_store or 'groups' not in user_crypto_store[creator_id]:
            return jsonify({'error': 'Group state not found'}), 400
        
        if group_id_b64 not in user_crypto_store[creator_id]['groups']:
            return jsonify({'error': 'Group not found in crypto store'}), 404
        
        group_state = user_crypto_store[creator_id]['groups'][group_id_b64]
        current_tree = group_state.get('tree')
        current_epoch = group_state.get('epoch', 0)
        
        # 2. Get all current members from database
        members_response = api_client.get_group_members(group_id_b64, token)
        current_members = members_response.get('members', [])
        
        # Check if new user is already a member
        if any(m.get('user_id') == new_user_id for m in current_members):
            return jsonify({'error': 'User already in group'}), 400
        
        # 3. Get new member's key package
        new_kp_bytes = api_client.get_latest_keypackage(new_user_id)
        if not new_kp_bytes:
            return jsonify({'error': 'No key package for new user'}), 400
        
        # 4. Rebuild the tree with all members (including new one)
        creator_kp_bytes = api_client.get_latest_keypackage(creator_id)
        creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes))
        creator_leaf = creator_kp.content.leaf_node
        
        # Create new empty group
        temp_group = api_client.create_empty_group(creator_leaf, "temp")
        new_tree = temp_group['tree']
        
        # Add all existing members (excluding creator, already at leaf 0)
        for member in current_members:
            if member.get('user_id') == creator_id:
                continue
            
            member_id = member.get('user_id')
            member_kp_bytes = api_client.get_latest_keypackage(member_id)
            if member_kp_bytes:
                member_kp = KeyPackage.deserialize(bytearray(member_kp_bytes))
                member_leaf = member_kp.content.leaf_node
                
                leaf_index = len(new_tree.leaves)
                while new_tree.nodes <= leaf_index * 2:
                    new_tree.extend()
                
                new_tree[leaf_index] = member_leaf
                new_tree[leaf_index]._leaf_index = leaf_index
                
                for i in range(len(new_tree.leaves)):
                    if isinstance(new_tree.leaves[i], LeafNode):
                        new_tree.leaves[i]._leaf_index = i
                
                new_tree.update_leaf_index()
                new_tree.update_node_index()
        
        # 5. Add the new member
        new_kp = KeyPackage.deserialize(bytearray(new_kp_bytes))
        new_leaf = new_kp.content.leaf_node
        
        new_leaf_index = len(new_tree.leaves)
        while new_tree.nodes <= new_leaf_index * 2:
            new_tree.extend()
        
        new_tree[new_leaf_index] = new_leaf
        new_tree[new_leaf_index]._leaf_index = new_leaf_index
        
        for i in range(len(new_tree.leaves)):
            if isinstance(new_tree.leaves[i], LeafNode):
                new_tree.leaves[i]._leaf_index = i
        
        new_tree.update_leaf_index()
        new_tree.update_node_index()
        
        # 6. Derive new epoch secret
        new_epoch_secret = api_client_2.derive_epoch_secret_from_tree(new_tree, cs)
        new_epoch = current_epoch + 1
        
        # 7. Generate joiner_secret for new member
        import secrets
        joiner_secret = secrets.token_bytes(32)
        
        # 8. Create Welcome for new member only
        welcome_bytes = api_client_3.create_welcome_simple(
            group_id_b64, new_user_id, joiner_secret, token
        )
        
        if welcome_bytes:
            api_client.insert_welcome(group_id_b64, new_user_id, welcome_bytes, token)
        
        # 9. Add new member to database
        new_leaf_index_in_db = len(current_members)
        api_client.add_group_member(group_id_b64, new_user_id, new_leaf_index_in_db, token)
        
        # 10. Update group epoch in database
        api_client.update_group_epoch(group_id_b64, new_epoch, token)
        
        # 11. Update creator's group state
        
        user_crypto_store[creator_id]['groups'][group_id_b64] = api_client.initialize_group_state_with_ratchet(
            group_id_b64=group_id_b64,
            tree=new_tree,
            cipher_suite=cs,
            my_leaf_index=0,  # Creator's leaf index
            current_epoch=new_epoch,
            my_user_id=creator_id
        )
        
        # 12. Create a Commit message for existing members (Alice) to update their state
        # This is simplified - in real MLS, you'd create a proper Commit
        commit_data = {
            'type': 'group_updated',
            'group_id': group_id_b64,
            'new_epoch': new_epoch,
            'new_member': {
                'user_id': new_user_id,
                'username': new_username,
                'leaf_index': new_leaf_index_in_db
            },
            'tree_serialized': base64.b64encode(new_tree.serialize()).decode('ascii')
        }
        
        

        # Notify all online members (including Alice) via WebSocket
        # Get all existing members (excluding the new member)
        updated_members_response = api_client.get_group_members(group_id_b64, token)
        all_members = updated_members_response.get('members', [])
        
        # Filter out the new member (they will get a Welcome separately)
        existing_members = [m for m in all_members if m.get('user_id') != new_user_id]
        
        print(f"📢 Notifying {len(existing_members)} existing members about group update")
        
        # Create update data for existing members
        commit_data = {
            'type': 'group_update',
            'group_id': group_id_b64,
            'new_epoch': new_epoch,
            'new_member': {
                'user_id': new_user_id,
                'username': new_username,
                'leaf_index': new_leaf_index_in_db
            }
        }
        
        # Debug logs to see where the notification fails
        print(f"📢 Existing members to notify: {[m.get('user_id') for m in existing_members]}")
        print(f"   Creator ID: {creator_id}")
        print(f"   New member: {new_user_id}")

        # Notify EACH existing member individually via FastAPI
        notify_url = f"http://localhost:8000/api/notify-group-update"
        
        for member in existing_members:
            member_id = member.get('user_id')
            if member_id == creator_id:
                # Creator already updated, but still notify to be safe
                pass
            
            try:
                response = requests.post(notify_url, json={
                    'user_id': member_id,
                    'group_id': group_id_b64,
                    'update_data': commit_data
                }, timeout=2)
                print(f"   Notified member {member_id}: {response.status_code}")
            except Exception as e:
                print(f"   Failed to notify {member_id}: {e}")
    

        return jsonify({
            'success': True,
            'group_id': group_id_b64,
            'new_epoch': new_epoch,
            'new_member': new_username,
            'message': f'Added {new_username} to group'
        })
        
    except Exception as e:
        print(f"Error adding member: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear session and remove from active sessions"""
    user_id = session.get('user_id')
    
    # Remove from active sessions
    if user_id and user_id in active_sessions:
       #print(f"Removing {user_id} from active_sessions")
        del active_sessions[user_id]
    
    # Remove PRIVATE key from server memory
    if user_id and user_id in user_crypto_store:
       #print(f"Clearing private crypto material for user {user_id}")
        del user_crypto_store[user_id]
    
    session.clear()
    
   #print(f"Active sessions after logout: {len(active_sessions)}")
    
    return jsonify({'success': True})



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
    
@app.route('/api/groups', methods=['GET'])
def get_user_groups():
    """Get all groups for the current user"""
    user_id = session.get('user_id')
    token = session.get('token')
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        groups_data = api_client.get_my_groups(token)
        
        if 'error' in groups_data:
            return jsonify({'error': groups_data['error']}), 400
        
        groups = groups_data.get('groups', [])
        enhanced_groups = []
        
        for group in groups:
            group_id_b64 = group.get('group_id')
            # Add hex version for frontend
            group_id_hex = base64.b64decode(group_id_b64).hex()
            
            crypto_info = {}
            if user_id in user_crypto_store and 'groups' in user_crypto_store[user_id]:
                if group_id_b64 in user_crypto_store[user_id]['groups']:
                    crypto_info = {
                        'has_keys': True,
                        'epoch': user_crypto_store[user_id]['groups'][group_id_b64].get('epoch')
                    }
            
            enhanced_groups.append({
                **group,
                **crypto_info,
                'group_id_hex': group_id_hex
            })
        
        return jsonify({
            'success': True,
            'groups': enhanced_groups
        })
        
    except Exception as e:
       #print(f"❌ Error getting user groups: {str(e)}")
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
           #print("------------------------------")
           print(f"Welcome ID:{welcome.get("id")}")
           #print("------------------------------")

        return jsonify({
            'success': True,
            'welcomes': welcomes
        })
        
    except Exception as e:
       #print(f"❌ Error fetching pending welcomes: {str(e)}")
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
           #print(f"✅ Tree restored for group {group_id_b64}")
            return tree
        except Exception as e:
           print(f"⚠️ Failed to restore tree: {e}")
    
    return None

@app.route('/api/messages/send', methods=['POST'])
def send_message():
   #print("="*50)
   #print("SEND MESSAGE ENDPOINT CALLED")
   #print("="*50)
    
    data = request.json
   #print(f"Request data: {data}")
    
    group_id_hex = data.get('group_id_hex')
    message_text = data.get('message')
    
   #print(f"group_id_hex: {group_id_hex}")
   #print(f"message_text: {message_text}")
    
    user_id = session.get('user_id')
    token = session.get('token')
    
   #print(f"user_id: {user_id}")
   #print(f"token exists: {bool(token)}")
    
    if not user_id or not token:
       #print("❌ Not authenticated")
        return jsonify({'error': 'Not authenticated'}), 401
    
    if not group_id_hex or not message_text:
       #print("❌ Missing fields")
        return jsonify({'error': 'Group ID hex and message required'}), 400
    
    # Convert hex to base64
    try:
        group_id_bytes = bytes.fromhex(group_id_hex)
        group_id_b64 = base64.b64encode(group_id_bytes).decode('ascii')
       #print(f"Converted to base64: {group_id_b64}")
    except Exception as e:
       #print(f"❌ Invalid hex: {e}")
        return jsonify({'error': f'Invalid group_id hex: {e}'}), 400
    
    # Check user_crypto_store
   #print(f"user_crypto_store keys: {list(user_crypto_store.keys()) if user_crypto_store else 'empty'}")
    
    if user_id not in user_crypto_store:
       #print(f"❌ User {user_id} not in crypto store")
        return jsonify({'error': 'User not found'}), 400
    
    if 'groups' not in user_crypto_store[user_id]:
       #print(f"❌ No groups for user {user_id}")
        return jsonify({'error': 'No groups found'}), 400
    
    if group_id_b64 not in user_crypto_store[user_id]['groups']:
       #print(f"❌ Group {group_id_b64} not found in user's groups")
       #print(f"Available groups: {list(user_crypto_store[user_id]['groups'].keys())}")
        return jsonify({'error': 'Group not found'}), 404
    
    group_state = user_crypto_store[user_id]['groups'][group_id_b64]
   #print(f"✅ Group state found, epoch: {group_state.get('epoch')}")
    
    try:
        result = api_client.encrypt_and_send_message(
            group_id_b64=group_id_b64,
            message_text=message_text,
            token=token,
            user_id=user_id,
            group_state=group_state
        )
        
       #print(f"Result from encrypt_and_send_message: {result}")
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
        
        return jsonify({'success': True, 'message': 'Message sent'})
        
    except Exception as e:
       #print(f"❌ Exception in encrypt_and_send_message: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
        
    
@app.route('/api/messages/get', methods=['POST'])
def get_messages():
    """Get and decrypt messages for a group - uses POST with JSON body"""
    data = request.json
    group_id_hex = data.get('group_id_hex')
    
    user_id = session.get('user_id')
    token = session.get('token')
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if not group_id_hex:
        return jsonify({'error': 'group_id_hex required'}), 400
    
    # Convert hex to base64 for lookup
    try:
        group_id_bytes = bytes.fromhex(group_id_hex)
        group_id_b64 = base64.b64encode(group_id_bytes).decode('ascii')
    except:
        return jsonify({'error': 'Invalid group_id hex'}), 400
    
   #print(f"📩 Getting messages for group: {group_id_b64} (hex: {group_id_hex})")
    
    # Get group state using base64
    if user_id not in user_crypto_store:
        return jsonify({'messages': []})
    
    if 'groups' not in user_crypto_store[user_id]:
        return jsonify({'messages': []})
    
    if group_id_b64 not in user_crypto_store[user_id]['groups']:
       #print(f"Group {group_id_b64} not found in user's groups")
        return jsonify({'messages': []})
    
    group_state = user_crypto_store[user_id]['groups'][group_id_b64]
    
    # Get messages from FastAPI
    result = api_client.get_group_messages(group_id_b64, token)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 400

   #print(f"📊 Received {len(result.get('messages', []))} messages from FastAPI")
    
    # Log the first message for debugging
    if result.get('messages'):
        first_msg = result['messages'][0]
       #print(f"📊 First message - sender: {first_msg.get('sender_username')}")
       #print(f"📊 First message - ciphertext length: {len(first_msg.get('ciphertext', ''))}")
       #print(f"📊 First message - epoch: {first_msg.get('epoch')}")
    
    # Decrypt messages
    decrypted_messages = []
    
    for msg in result.get('messages', []):
        try:
           #print(f"🔓 Attempting to decrypt message from {msg.get('sender_username')}")
            decrypted = api_client.decrypt_message(msg, group_state, user_id)
            if decrypted:
               #print(f"✅ Decrypted: {decrypted.get('text')[:50]}")
                decrypted_messages.append(decrypted)
            #else:
               #print(f"❌ Decryption returned None")
        except Exception as e:
           #print(f"⚠️ Failed to decrypt message: {e}")
            import traceback
            traceback.print_exc()
            decrypted_messages.append({
                'message_id': msg.get('message_id'),
                'sender_username': msg.get('sender_username', 'Unknown'),
                'text': f'[Encrypted - Error: {str(e)[:50]}]',
                'created_at': msg.get('created_at')
            })
    
    return jsonify({
        'success': True,
        'messages': decrypted_messages
    })
    
    
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
    

@app.route('/api/welcomes/process', methods=['POST'])
def process_welcome():
    """Process a welcome message and join a group"""
    data = request.json
    
    welcome_b64 = data.get('welcome_b64')
    group_id_b64 = data.get('group_id')
    welcome_id = data.get('welcome_id')
    
    if not welcome_id:
        return jsonify({'error': 'Missing welcome_id'}), 400
    
    user_id = session.get('user_id')
    username = session.get('username')
    token = session.get('token')
    
    if not user_id or not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Find the correct private key for this welcome
    if user_id not in user_crypto_store or 'keys' not in user_crypto_store[user_id]:
        return jsonify({'error': 'No keys found'}), 400
    
    # Parse welcome to get key package reference
    welcome_bytes = base64.b64decode(welcome_b64)
    mls_msg = MLSMessage.deserialize(bytearray(welcome_bytes))
    welcome = mls_msg.msg_content
    
    if not welcome.secrets:
        return jsonify({'error': 'No secrets in welcome'}), 400
    
    encrypted_secret = welcome.secrets[0]
    key_package_ref = encrypted_secret.new_member.to_bytes().hex()
    
    # Find matching private key
    init_priv = None
    for ref, key_data in user_crypto_store[user_id]['keys'].items():
        if ref == key_package_ref or ref.endswith(key_package_ref[-16:]):
            init_priv = key_data.get('init_priv')
            break
    
    if not init_priv:
        return jsonify({'error': 'No matching private key found'}), 400
    
    # 1. Get joiner_secret from Welcome
    joiner_secret = api_client_3.process_welcome_simple(welcome_b64, init_priv)
    
    # 2. Build tree using the working replay method
    tree, current_epoch, members = api_client.build_tree_by_replay(group_id_b64, token)
    
    # 6. Now we have the same tree as the creator
    print(f"   Final tree has {len(tree.leaves)} leaves, {tree.nodes} nodes")
    
    # 7. Derive epoch_secret from the tree
    # Ensure all leaf indices are set
    for i in range(len(tree.leaves)):
        if isinstance(tree.leaves[i], LeafNode):
            tree.leaves[i]._leaf_index = i
    
    tree.update_leaf_index()
    tree.update_node_index()
    
    # Now derive epoch_secret
    root_secret = tree.hash(cs)
    epoch_secret = DeriveSecret(cs, root_secret, b"epoch")
    
    
    # 9. Find my leaf index
    my_leaf_index = None
    for member in members:
        if member.get('user_id') == user_id:
            my_leaf_index = member.get('leaf_index')
            break
    
    # 10. Store group state
    # ✅ USE NEW FUNCTION
    if user_id not in user_crypto_store:
        user_crypto_store[user_id] = {}
    if 'groups' not in user_crypto_store[user_id]:
        user_crypto_store[user_id]['groups'] = {}
    
    group_state = api_client.initialize_group_state_with_ratchet(
        group_id_b64=group_id_b64,
        tree=tree,
        cipher_suite=cs,
        my_leaf_index=my_leaf_index,
        current_epoch=current_epoch,
        my_user_id=user_id
    )
    
    user_crypto_store[user_id]['groups'][group_id_b64] = group_state
    
    # Mark welcome as delivered
    api_client.mark_welcome_delivered(welcome_id, token)
    
    print(f"✅ User {username} joined group with tree ({len(tree.leaves)} leaves)")
    
    return jsonify({
        'success': True,
        'group_id': group_id_b64,
        'epoch': group_state['epoch'],
        'my_leaf_index': group_state.get('my_leaf_index'),
        'message': 'Successfully joined group'
    })

@app.route('/api/groups/create-with-online', methods=['POST'])
def create_group_with_online():
    """Create a group with all online users (excluding creator)"""
    data = request.json
    group_name = data.get('group_name', 'MLS Test Group')
    online_users = data.get('users', [])
    creator_id = session.get('user_id')
    token = session.get('token')
    creator_username = session.get('username')
    
    if not creator_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # STEP 1-3: Get creator's key package and create empty group
    creator_kp_bytes = api_client.get_latest_keypackage(creator_id)
    if not creator_kp_bytes:
        return jsonify({'error': 'No key package found for creator'}), 400
    
    creator_private_key = user_crypto_store[creator_id].get('private_key')
    if not creator_private_key:
        return jsonify({'error': 'Private key not found'}), 400

    creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes))
    creator_leaf = creator_kp.content.leaf_node

    # Create empty group
    group = api_client.create_empty_group(creator_leaf, creator_username)
    group_id_b64 = group['group_id_b64']
    
    # Save group to database
    api_client.create_group_with_id(group_name, 1, token, group_id_b64)
    api_client.add_group_member(group_id_b64, creator_id, 0, token)
    
    joiner_secrets = []
    leaf_index = 1
    
    # Add each member to the tree (this updates the group object)
    for user in online_users:
        user_id = user.get('user_id')
        username = user.get('username')
        
        user_kp_bytes = api_client.get_latest_keypackage(user_id)
        if not user_kp_bytes:
            continue
        
        # Add to tree and get joiner_secret
        joiner_secret, group = api_client_3.add_member_to_tree(
            group, user_id, creator_private_key
        )
        joiner_secrets.append((user_id, joiner_secret))
        
        # Add to database
        api_client.add_group_member(group_id_b64, user_id, leaf_index, token)
        leaf_index += 1
    
    # Create simple Welcomes
    for user_id, joiner_secret in joiner_secrets:
        welcome_bytes = api_client_3.create_welcome_simple(
            group_id_b64, user_id, joiner_secret, token
        )
        if welcome_bytes:
            api_client.insert_welcome(group_id_b64, user_id, welcome_bytes, token)
    
    # IMPORTANT: Use the EXISTING tree from the group object, don't rebuild!
    final_tree = group['tree']
    final_epoch = group['epoch']
    
    # Get members from database for count
    members_response = api_client.get_group_members(group_id_b64, token)
    members = members_response.get('members', [])
    
    # Fix leaf indices on the existing tree
    for i in range(len(final_tree.leaves)):
        if isinstance(final_tree.leaves[i], LeafNode):
            final_tree.leaves[i]._leaf_index = i
    
    final_tree.update_leaf_index()
    final_tree.update_node_index()
    
    # Derive epoch_secret from the tree
    epoch_secret = api_client_2.derive_epoch_secret_from_tree(final_tree, cs)
    
    # Store final group state
    if creator_id not in user_crypto_store:
        user_crypto_store[creator_id] = {}
    if 'groups' not in user_crypto_store[creator_id]:
        user_crypto_store[creator_id]['groups'] = {}
    
    user_crypto_store[creator_id]['groups'][group_id_b64] = api_client.initialize_group_state_with_ratchet(
        group_id_b64=group_id_b64,
        tree=final_tree,
        cipher_suite=cs,
        my_leaf_index=0,  # Creator is leaf 0
        current_epoch=final_epoch,
        my_user_id=creator_id
    )
    
    # Update group epoch in database
    api_client.update_group_epoch(group_id_b64, final_epoch, token)
    
    return jsonify({
        'success': True,
        'group_id': group_id_b64,
        'group_name': group_name,
        'member_count': len(online_users) + 1,
        'members': [creator_username] + [u.get('username') for u in online_users]
    })

@app.route('/api/groups/search', methods=['GET'])
def search_groups():
    """Proxy search request to FastAPI (avoids CORS)"""
    group_name = request.args.get('group_name')
    token = session.get('token')
    
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if not group_name:
        return jsonify({'error': 'group_name required'}), 400
    
    try:
        import requests
        response = requests.get(
            f"http://localhost:8000/api/groups/search?group_name={group_name}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({'error': 'Failed to search groups'}), response.status_code
            
    except Exception as e:
        print(f"Error searching groups: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/groups/request-join', methods=['POST'])
def request_join_group():
    """User requests to join a group"""
    data = request.json
    group_id_b64 = data.get('group_id')
    group_name = data.get('group_name')
    
    user_id = session.get('user_id')
    username = session.get('username')
    token = session.get('token')
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get group details to find creator
        group_details = api_client.get_group_details(group_id_b64, token)
        if 'error' in group_details:
            return jsonify({'error': 'Group not found'}), 404
        
        creator_id = group_details.get('creator_user_id')
        
        # Send WebSocket notification to creator via FastAPI
        notify_url = f"http://localhost:8000/api/notify-join-request"
        response = requests.post(notify_url, json={
            'creator_id': creator_id,
            'requester_id': user_id,
            'requester_username': username,
            'group_id': group_id_b64,
            'group_name': group_name
        }, timeout=2)
        
        return jsonify({
            'success': True,
            'message': f'Join request sent to group creator'
        })
        
    except Exception as e:
        print(f"Error requesting join: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/debug/user-state', methods=['GET'])
def debug_user_state():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    result = {}
    if user_id in user_crypto_store and 'groups' in user_crypto_store[user_id]:
        for group_id, state in user_crypto_store[user_id]['groups'].items():
            result[group_id] = {
                'epoch': state.get('epoch'),
                'leaves': len(state.get('tree', {}).leaves) if state.get('tree') else 0,
                'tree_hash': state.get('tree').hash(cs).hex()[:16] if state.get('tree') else None
            }
    
    return jsonify(result)

if __name__ == '__main__': 
    app.run(debug=True, host='0.0.0.0', port=5000)

