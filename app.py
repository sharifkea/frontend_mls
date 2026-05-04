# app.py
import uuid, os, time, sys, json, base64, api_client,api_client_2,api_client_3,create_keypakage,secrets,requests


from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from flask_debugtoolbar import DebugToolbarExtension

import warnings

import save_local
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

app.config['DEBUG_TB_PROFILER_ENABLED'] = True
toolbar = DebugToolbarExtension(app)

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
    total_login_time=0
    
    print(f"Login attempt for username: {username}")
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    try:
        start = time.perf_counter()
        # 1. Login to get user_id and token
        result = api_client.login_user(username, password)
       #print(f"Login result: {result}")
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 401
        
        user_id = result['user_id']
        token = result['access_token']
        
        end = time.perf_counter()
        user_pass_db_ms = (end - start) * 1000
        print(f"⏱️ Time for user authentication and database access: {user_pass_db_ms:.2f}ms")
        total_login_time += user_pass_db_ms
        start = time.perf_counter()
        
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
        end = time.perf_counter()
        not_gro_cre_ms = (end - start) * 1000
        print(f"⏱️ Time for notifying group creators: {not_gro_cre_ms:.2f}ms")
        total_login_time += not_gro_cre_ms
        start = time.perf_counter()
        # 2. Generate FRESH key package for this session
        #print(f"Generating fresh key package for {username}...")
        private_key, init_priv, key_package_bytes = create_keypakage.GeneratKeyPackage(username)

        end = time.perf_counter()
        gen_key_pak_ms = (end - start) * 1000
        print(f"⏱️ Time for generating key package: {gen_key_pak_ms:.2f}ms")
        total_login_time += gen_key_pak_ms
        start = time.perf_counter()
        # 3. Upload key package to backend database
       #print(f"Uploading new key package (old ones will be deactivated)...")
        upload_result = api_client.upload_keypackage(user_id, key_package_bytes)
        # Deserialize to get the proper MLS reference hash
        
        end = time.perf_counter()
        sav_key_pak_db_ms = (end - start) * 1000
        print(f"⏱️ Time for saving key package to database: {sav_key_pak_db_ms:.2f}ms")
        total_login_time += sav_key_pak_db_ms

        start = time.perf_counter()
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
        
        end = time.perf_counter()
        sav_act_ses_ms = (end - start) * 1000
        print(f"⏱️ Time for saving active session: {sav_act_ses_ms:.2f}ms")
        total_login_time += sav_act_ses_ms
        print(f"✅ User {username} logged in successfully! ⏱️Total login time: {total_login_time:.2f}ms")
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
        start = time.perf_counter()
        new_group_state = update_state(user_id, group_id_b64, token)
        if new_group_state:
            user_crypto_store[user_id]['groups'][group_id_b64] = new_group_state
            end = time.perf_counter()
            tim_gr_sta_ms = (end - start) * 1000
            print(f"⏱️📝 Time for updating group state: {tim_gr_sta_ms:.2f}ms")
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Failed to update group state'}), 400
        
        
        
    except Exception as e:
        print(f"Error updating group state: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/groups/add-member', methods=['POST'])
def add_member_to_group():
    """Creator adds a new member to an existing group"""
    
    timings = {}
    total_start = time.perf_counter()
    
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
        # ========== STEP 1: Get current group state ==========
        step_start = time.perf_counter()
        if creator_id not in user_crypto_store or 'groups' not in user_crypto_store[creator_id]:
            return jsonify({'error': 'Group state not found'}), 400
        
        if group_id_b64 not in user_crypto_store[creator_id]['groups']:
            return jsonify({'error': 'Group not found in crypto store'}), 404
        
        group_state = user_crypto_store[creator_id]['groups'][group_id_b64]

        new_tree = group_state.get('tree')
        current_epoch = group_state.get('epoch', 0)
        new_leaf_index = group_state.get('member_count', 0)
        final_secret = group_state.get('final_secret', bytes(32))   
        
        # 2. Get all current members from database
        current_members = group_state.get('members_list', [])
        timings['1_get_group_state'] = time.perf_counter() - step_start
        current_members_ids = [m.get('user_id') for m in current_members if m.get('user_id') != creator_id]

        
        # ========== STEP 2: Check if new user is already a member ==========
        step_start = time.perf_counter()
        if any(m.get('user_id') == new_user_id for m in current_members):
            return jsonify({'error': 'User already in group'}), 400
        else:
            all_group_ids = current_members_ids + [new_user_id]
            print(f"✅ User {new_user_id} is not currently a member, proceeding to add")
        if any(m.get('user_id') == creator_id for m in current_members):
            all_group_ids.append(creator_id)  # Ensure creator is included for batch key package fetch
            print(f"✅ Including creator {creator_id} in batch key package fetch")
        
        timings['2_check_membership'] = time.perf_counter() - step_start
        
        # ========== STEP 3: Get batch key packages ==========
        step_start = time.perf_counter()
        batch_keypackages = api_client.get_batch_latest_keypackages(all_group_ids, token)
        timings['3_batch_keypackages'] = time.perf_counter() - step_start
        
        # ========== STEP 4: Get creator and new member key packages ==========
        step_start = time.perf_counter()
        creator_kp_bytes = batch_keypackages.get(creator_id)
        if not creator_kp_bytes:
            return jsonify({'error': 'No key package found for creator'}), 400
        
        creator_private_key = user_crypto_store[creator_id].get('private_key')
        if not creator_private_key:
            return jsonify({'error': 'Private key not found'}), 400

        creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes["key_package"]))

        new_kp_bytes = batch_keypackages.get(new_user_id)
        if not new_kp_bytes:
            return jsonify({'error': 'No key package for new user'}), 400
        timings['4_get_kp'] = time.perf_counter() - step_start
        
        # ========== STEP 5: Add the new member to tree ==========
        step_start = time.perf_counter()
        new_kp = KeyPackage.deserialize(bytearray(new_kp_bytes["key_package"]))
        new_leaf = new_kp.content.leaf_node
        
        while new_tree.nodes <= new_leaf_index:
            new_tree.extend()
        
        new_tree[new_leaf_index] = new_leaf
        new_tree[new_leaf_index]._leaf_index = new_leaf_index
        
        for i in range(len(new_tree.leaves)):
            if isinstance(new_tree.leaves[i], LeafNode):
                new_tree.leaves[i]._leaf_index = i
        
        new_tree.update_leaf_index()
        new_tree.update_node_index()
        timings['5_add_to_tree'] = time.perf_counter() - step_start
        
        # ========== STEP 6: Derive new epoch secret ==========
        step_start = time.perf_counter()
        new_epoch_secret, new_root_secret = api_client_2.derive_epoch_secret_from_tree(new_tree, cs, final_secret)
        new_epoch = current_epoch + 1
        timings['6_derive_secrets'] = time.perf_counter() - step_start
        
        # ========== STEP 7: Create Welcome ==========
        step_start = time.perf_counter()
        welcome_bytes = api_client_3.create_welcome_simple(
            group_id_b64, new_user_id, final_secret, new_kp_bytes["key_package"], token
        )
        timings['7_create_welcome'] = time.perf_counter() - step_start
        
        # ========== STEP 8: Store welcome and add to database ==========
        step_start = time.perf_counter()
        if welcome_bytes:
            api_client.insert_welcome(group_id_b64, new_user_id, welcome_bytes, token)
        
        api_client.add_group_member(group_id_b64, new_user_id, new_leaf_index, token)
        api_client.update_group_epoch(group_id_b64, new_epoch, token)
        timings['8_db_operations'] = time.perf_counter() - step_start
        
        # ========== STEP 9: Get updated members ==========
        step_start = time.perf_counter()
        updated_members_response = api_client.get_group_members(group_id_b64, token)
        all_members = updated_members_response.get('members', [])
        timings['9_get_members'] = time.perf_counter() - step_start
        
        # ========== STEP 10: Save to local store and update state ==========
        step_start = time.perf_counter()
        save_local.save_final_secret(creator_id, group_id_b64, final_secret)
        
        user_crypto_store[creator_id]['groups'][group_id_b64] = initialize_group_state_with_keys(
            group_id_b64=group_id_b64,
            tree=new_tree,
            cipher_suite=cs,
            my_leaf_index=0,
            current_epoch=new_epoch,
            my_user_id=creator_id,
            members=all_members,
            epoch_secret=new_epoch_secret,
            final_secret=final_secret,
            root_secret=new_root_secret
        )
        timings['10_store_state'] = time.perf_counter() - step_start
        
        # ========== STEP 11: Notify other members ==========
        step_start = time.time()
    
        #existing_members = [m for m in all_members if m.get('user_id') != new_user_id and m.get('user_id') != creator_id]
        
        
            
        print(f"📢 Batch notifying {len(current_members_ids)} existing members about group update")
        
        commit_data = {
            'type': 'group_update',
            'group_id': group_id_b64,
            'new_epoch': new_epoch,
            'new_member': {
                'user_id': new_user_id,
                'username': new_username,
                'leaf_index': new_leaf_index
            }
        }
        
        # ✅ SINGLE BATCH CALL instead of loop
        result = api_client.notify_group_update_batch(
            group_id_b64, 
            current_members_ids, 
            commit_data, 
            token
        )
        
        print(f"   Batch notification result: {result}")
        
        
        timings['11_notify_members'] = time.time() - step_start
        
        total_time = time.perf_counter() - total_start
        
        # ========== PRINT SUMMARY ==========
        print(f"\n{'='*50}")
        print(f"⏱️ ADD MEMBER TO GROUP TIMINGS for {new_username}")
        print(f"{'='*50}")
        for key, value in timings.items():
            print(f"   {key}: {value:.3f}s")
        print(f"   TOTAL: {total_time:.3f}s")
        print(f"{'='*50}\n")

        return jsonify({
            'success': True,
            'group_id': group_id_b64,
            'new_epoch': new_epoch,
            'new_member': new_username,
            'message': f'Added {new_username} to group',
            'timings': timings,
            'total_time': total_time
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
        start = time.perf_counter()
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

        end = time.perf_counter()
        get_groups_db_ms = (end - start) * 1000
        print(f"⏱️ Time for getting groups from database: {get_groups_db_ms:.2f}ms")

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
        start = time.perf_counter()
    
        result = api_client.encrypt_and_send_message(
            group_id_b64=group_id_b64,
            message_text=message_text,
            token=token,
            user_id=user_id,
            group_state=group_state
        )
        
        end = time.perf_counter()
        elapsed_ms = (end - start) * 1000
        print(f"⏱️ [PERFORMANCE] encrypt_and_send_message took: {elapsed_ms:.2f}ms")
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
    """Get and decrypt NEW messages only (not already displayed)"""
    data = request.json
    group_id_hex = data.get('group_id_hex')
    
    user_id = session.get('user_id')
    token = session.get('token')
    
    if not user_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if not group_id_hex:
        return jsonify({'error': 'group_id_hex required'}), 400
    
    # Convert hex to base64
    try:
        group_id_bytes = bytes.fromhex(group_id_hex)
        group_id_b64 = base64.b64encode(group_id_bytes).decode('ascii')
    except:
        return jsonify({'error': 'Invalid group_id hex'}), 400
    
     # Initialize user structure if needed
    if user_id not in user_crypto_store:
        user_crypto_store[user_id] = {}
    if 'groups' not in user_crypto_store[user_id]:
        user_crypto_store[user_id]['groups'] = {}
    
    # ✅ FIRST: Get group_state from store
    group_state = user_crypto_store[user_id]['groups'].get(group_id_b64)
        
    if not group_state:
        print(f"⚠️ Group state missing for {group_id_b64}, restoring on demand...")
        new_group_state = update_state(user_id, group_id_b64, token)
        if new_group_state:
            user_crypto_store[user_id]['groups'][group_id_b64] = new_group_state
            group_state = new_group_state
        else:
            return jsonify({'error': 'Could not restore group state'}), 400
        
    # Get group state
    if user_id not in user_crypto_store:
        return jsonify({'messages': []})
    
    if 'groups' not in user_crypto_store[user_id]:
        return jsonify({'messages': []})
    
    if group_id_b64 not in user_crypto_store[user_id]['groups']:
        return jsonify({'messages': []})
    
    start = time.perf_counter()
    # ✅ NOW this exists because we use initialize_group_state_with_keys
    last_message_id = group_state.get('last_displayed_message_id')
    displayed_messages = group_state.get('displayed_messages', [])
    joined_epoch = group_state.get('epoch', 0)
    latest_epoch = group_state.get('group_last_epoch', joined_epoch)
    
    print(f"📊 User joined at epoch: {joined_epoch}, group latest: {latest_epoch}")
    # Build URL with since_epoch parameter
    params = {"limit": 50, "since_epoch": joined_epoch}
    # Build URL with since_message_id if available
    group_id_hex_for_url = group_id_bytes.hex()
    url = f"http://localhost:8000/groups/{group_id_hex_for_url}/messages"
    if last_message_id:
        params["since_message_id"] = last_message_id
    # Also track the latest epoch for the group (for updates)
    # Fetch messages from FastAPI
    try:
        import requests
        response = requests.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}"}
        )
        result = response.json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 400
    
    end = time.perf_counter()
    get_mes_db_ms = (end - start) * 1000
    print(f"⏱️Time to Get_messages from DB took: {get_mes_db_ms:.2f}ms")

    #start = time.perf_counter()
    # Decrypt only NEW messages (not already displayed)
    decrypted_messages = []
    latest_message_id = last_message_id
    elapsed_ms = 0
    for msg in result.get('messages', []):
        # ✅ Skip if already displayed
        if msg.get('message_id') in displayed_messages:
            continue
            
        try:
            start = time.perf_counter()
            
            decrypted = api_client.decrypt_message(msg, group_state, user_id)
            
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            print(f"⏱️ Time to decrypt_message took: {elapsed_ms:.2f}ms")

            if decrypted:
                decrypted_messages.append(decrypted)
                latest_message_id = msg.get('message_id')
        except Exception as e:
            print(f"⚠️ Failed to decrypt message: {e}")
            decrypted_messages.append({
                'message_id': msg.get('message_id'),
                'sender_username': msg.get('sender_username', 'Unknown'),
                'text': f'[Encrypted - Error: {str(e)[:50]}]',
                'created_at': msg.get('created_at')
            })
            latest_message_id = msg.get('message_id')
    
    # ✅ Update tracking
    if latest_message_id and latest_message_id != last_message_id:
        group_state['last_displayed_message_id'] = latest_message_id
        for msg in decrypted_messages:
            if msg.get('message_id') and msg.get('message_id') not in displayed_messages:
                displayed_messages.append(msg.get('message_id'))
        group_state['displayed_messages'] = displayed_messages

    print(f"<tool_call>Total decryption message time: {get_mes_db_ms+elapsed_ms:.2f}ms")

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
    user_name = session.get('username', 'Unknown')
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
    final_secret = api_client_3.process_welcome_simple(welcome_b64, init_priv)
    
    if final_secret:
        print(f"\n🔍 Final secret for: {user_name} is  {final_secret[:8].hex()}")
    else:
        print(f"\n🔍 No final secret found for {user_name}")

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
    epoch_secret = DeriveSecret(cs, root_secret+final_secret, b"epoch")
    
    
    # 9. Find my leaf index
    my_leaf_index = None
    for member in members:
        if member.get('user_id') == user_id:
            my_leaf_index = member.get('leaf_index')
            break
    
    # 10. Store group state
    if user_id not in user_crypto_store:
        user_crypto_store[user_id] = {}
    if 'groups' not in user_crypto_store[user_id]:
        user_crypto_store[user_id]['groups'] = {}
    
    #save to local store
    save_local.save_final_secret(user_id, group_id_b64, final_secret)

    group_state = initialize_group_state_with_keys(
        group_id_b64=group_id_b64,
        tree=tree,
        cipher_suite=cs,
        my_leaf_index=my_leaf_index,
        current_epoch=current_epoch,
        my_user_id=user_id,
        members=members,
        epoch_secret=epoch_secret,
        final_secret=final_secret,
        root_secret=root_secret
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
    """Create a group with all online users (optimized with timers)"""
    import time
    
    data = request.json
    group_name = data.get('group_name', 'MLS Test Group')
    online_users = data.get('users', [])
    creator_id = session.get('user_id')
    token = session.get('token')
    creator_username = session.get('username')
    
    if not creator_id or not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    timings = {}
    total_start = time.time()
    
    # ========== STEP 1: Get creator's key package ==========
    step_start = time.time()
    user_ids = [user.get('user_id') for user in online_users]
    print(f"📦 Requesting key packages for users: {user_ids}")
    
    all_group_ids = user_ids + [creator_id]  # Include creator in batch fetch
    print(f"📦 Fetching key packages for all group members : {all_group_ids}")

    batch_keypackages = api_client.get_batch_latest_keypackages(all_group_ids, token)

    creator_kp_bytes = batch_keypackages.get(creator_id)
    if not creator_kp_bytes:
        return jsonify({'error': 'No key package found for creator'}), 400
    
    creator_private_key = user_crypto_store[creator_id].get('private_key')
    if not creator_private_key:
        return jsonify({'error': 'Private key not found'}), 400

    creator_kp = KeyPackage.deserialize(bytearray(creator_kp_bytes["key_package"]))
    creator_leaf = creator_kp.content.leaf_node
    timings['1_get_creator_kp'] = time.time() - step_start
    print(f"🗝️✅ Fetched {len(batch_keypackages)} key packages in {timings['1_get_creator_kp']:.3f}s")

    # ========== STEP 2: Create empty group ==========
    step_start = time.time()
    group = api_client.create_empty_group(creator_leaf, creator_username)
    group_id_b64 = group['group_id_b64']
    timings['2_create_empty_group'] = time.time() - step_start
    
    # ========== STEP 3: Save group to database ==========
    step_start = time.time()
    api_client.create_group_with_id(group_name, 1, token, group_id_b64)
    timings['3_create_group'] = time.time() - step_start  
    step_start = time.time()
    api_client.add_group_member(group_id_b64, creator_id, 0, token)
    timings['4_save_to_db'] = time.time() - step_start    
    
    # ========== STEP 5: Add members to tree (optimized) ==========
    step_start = time.time()
    user_ids = [user.get('user_id') for user in online_users]
    members_for_db = []
    leaf_index = 1
    final_secret= None
    
    for user in online_users:
        user_id = user.get('user_id')
        username = user.get('username')
        
        kp_data = batch_keypackages.get(user_id)
        if not kp_data:
            print(f"⚠️ No key package for {username}, skipping")
            continue
        
        # Add to tree (using optimized function that doesn't update indices per member)
        joiner_secret, group = api_client_3.add_member_to_tree_optimized(
            group, user_id, creator_private_key, leaf_index, kp_data["key_package"]
        )
        #joiner_secrets.append((user_id, joiner_secret))
        final_secret = joiner_secret  # Keep overwriting to get the final one after all adds
        members_for_db.append({"user_id": user_id, "leaf_index": leaf_index, "username": username})
        leaf_index += 1
    
    timings['5_add_members_loop'] = time.time() - step_start
    #print(f"➕ Added {len(joiner_secrets)} members in {timings['5_add_members_loop']:.3f}s")
    
    # ========== STEP 6: Finalize tree indices once ==========
    step_start = time.time()
    api_client_3.finalize_tree_indices(group)
    timings['6_finalize_indices'] = time.time() - step_start
    print(f"🌲 Finalized tree indices in {timings['6_finalize_indices']:.3f}s")
    
    # ========== STEP 7: BATCH - Add all members to database ==========
    step_start = time.time()
    if members_for_db:
        api_client.add_group_members_batch(group_id_b64, members_for_db, token)
    timings['7_batch_db_add'] = time.time() - step_start
    print(f"💾 Added {len(members_for_db)} members to DB in batch: {timings['7_batch_db_add']:.3f}s")
    
    # ========== STEP 8: Batch create and store Welcomes ==========
    step_start = time.time()

    # First, create all welcome bytes (this is crypto work, can't batch)
    welcome_list = []
    for user_id in user_ids:
        kp_data = batch_keypackages.get(user_id)
        if kp_data:
            welcome_bytes = api_client_3.create_welcome_simple(
                group_id_b64, user_id, final_secret, kp_data["key_package"], token
            )
            if welcome_bytes:
                welcome_list.append({
                    "to_user_id": user_id,
                    "welcome_b64": base64.b64encode(welcome_bytes).decode('ascii')
                })

    timings['8a_create_welcomes_crypto'] = time.time() - step_start
    print(f"🔐 Created {len(welcome_list)} welcomes (crypto) in {timings['8a_create_welcomes_crypto']:.3f}s")

    # Then store all welcomes in ONE batch HTTP call
    if welcome_list:
        step_start = time.time()
        api_client.insert_welcome_batch(group_id_b64, welcome_list, token)
        timings['8b_batch_store_welcomes'] = time.time() - step_start
        print(f"💾 Batch stored {len(welcome_list)} welcomes in {timings['8b_batch_store_welcomes']:.3f}s")
    
    # ========== STEP 9: Final tree processing ==========
    step_start = time.time()
    final_tree = group['tree']
    final_epoch = group['epoch']
    
    # Get members from database for state
    members_response = api_client.get_group_members(group_id_b64, token)
    members = members_response.get('members', [])
    timings['9_get_members'] = time.time() - step_start
    
    # ========== STEP 10: Derive secrets ==========
    step_start = time.time()
    epoch_secret, root_secret = api_client_2.derive_epoch_secret_from_tree(final_tree, cs,final_secret)
    timings['10_derive_secrets'] = time.time() - step_start
    
    # ========== STEP 11: Store group state ==========
    step_start = time.time()
    if creator_id not in user_crypto_store:
        user_crypto_store[creator_id] = {}
    if 'groups' not in user_crypto_store[creator_id]:
        user_crypto_store[creator_id]['groups'] = {}
    
    if final_secret:
        print(f"\n🔍 Final secret for: {creator_username} is  {final_secret[:8].hex()}")
    else:
        print(f"\n🔍 No final secret found for {creator_username}")
    
    #save to local store
    save_local.save_final_secret(creator_id, group_id_b64, final_secret)
    
    user_crypto_store[creator_id]['groups'][group_id_b64] = initialize_group_state_with_keys(
        group_id_b64=group_id_b64,
        tree=final_tree,
        cipher_suite=cs,
        my_leaf_index=0,
        current_epoch=final_epoch,
        my_user_id=creator_id,
        members=members,
        epoch_secret=epoch_secret,
        final_secret=final_secret,
        root_secret=root_secret
    )
    timings['11_store_state'] = time.time() - step_start
    
    # ========== STEP 12: Update group epoch in database ==========
    step_start = time.time()
    api_client.update_group_epoch(group_id_b64, final_epoch, token)
    timings['12_update_epoch'] = time.time() - step_start
    
    total_time = time.time() - total_start
    
    # ========== PRINT SUMMARY ==========
    print(f"\n{'='*50}")
    print(f"⏱️ OPTIMIZED TOTAL TIME: {total_time:.3f}s for {len(online_users)} members")
    print(f"{'='*50}")
    print("📊 DETAILED TIMINGS:")
    for key, value in timings.items():
        print(f"   {key}: {value:.3f}s")
    
    # Compare with previous runs
        
    print(f"{'='*50}\n")
    
    return jsonify({
        'success': True,
        'group_id': group_id_b64,
        'group_name': group_name,
        'member_count': len(online_users) + 1,
        'members': [creator_username] + [u.get('username') for u in online_users],
        'timings': timings,
        'total_time': total_time
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

def update_state(user_id, group_id_b64, token=None):
    print(f"\n🔄 Updating group state for user {user_id}")
    
    # Initialize user crypto store if needed
    if user_id not in user_crypto_store:
        user_crypto_store[user_id] = {}
    if 'groups' not in user_crypto_store[user_id]:
        user_crypto_store[user_id]['groups'] = {}
    
    # Get final_secret from stored state or local file
    group_state = user_crypto_store[user_id]['groups'].get(group_id_b64)
    if group_state:
        final_secret = group_state.get('final_secret', bytes(32))
    else:
        print(f"⚠️Attempting to load final_secret from local store...")
        final_secret = save_local.get_final_secret(user_id, group_id_b64)
        print(f"🗝️ final_secret (first 8 bytes): {final_secret[:8].hex()}")
        if final_secret and isinstance(final_secret, str):
            final_secret = bytes.fromhex(final_secret) if final_secret.startswith('0x') else final_secret.encode()
    
    if not final_secret:
        print(f"⚠️ No final_secret found for user {user_id}, group {group_id_b64}")
        return None
    
    if not token:
        print(f"⚠️ No token provided for user {user_id}")
        return None
    
    start = time.perf_counter()
    # Build tree using the working replay method
    tree, current_epoch, members = api_client.build_tree_by_replay(group_id_b64, token)
    
    end = time.perf_counter()
    build_tree_ms = (end - start) * 1000
    print(f"⏱️ Time for building tree: {build_tree_ms:.2f}ms")
    # Derive epoch secret
    root_secret = tree.hash(cs)
    print(f"🫚   Derived root_secret: {root_secret[:8].hex()}...")
    epoch_secret = DeriveSecret(cs, root_secret + final_secret, b"epoch")
    print(f"🙊   Derived epoch_secret: {epoch_secret[:8].hex()}...")
    
    # Find my leaf index
    my_leaf_index = None
    for member in members:
        if member.get('user_id') == user_id:
            my_leaf_index = member.get('leaf_index')
            break
    
    new_group_state = initialize_group_state_with_keys(
        group_id_b64=group_id_b64,
        tree=tree,
        cipher_suite=cs,
        my_leaf_index=my_leaf_index,
        current_epoch=current_epoch,
        my_user_id=user_id,
        members=members,
        epoch_secret=epoch_secret,
        final_secret=final_secret,
        root_secret=root_secret
    )
    
    print(f"✅ User {user_id} group state updated")
    print(f"   Tree has {len(tree.leaves)} leaves, epoch {current_epoch}")
    
    return new_group_state

def initialize_group_state_with_keys(group_id_b64: str, tree, cipher_suite, my_leaf_index: int, current_epoch: int, my_user_id: str, members: list, epoch_secret=None,final_secret=None, root_secret=None) -> dict:
    """
    Initialize group state with per-sender root key tracking and message read tracking.
    """
    from api_client_2 import derive_epoch_secret_from_tree
    
    # Derive initial root secret
    #epoch_secret, root_secret = derive_epoch_secret_from_tree(tree, cipher_suite)
    
    # Initialize per-sender root keys
    per_sender_roots = {}
    for member in members:
        sender_id = member.get('user_id')
        per_sender_roots[sender_id] = {
            'root_secret': root_secret,
            'generation': 0,
            'last_used': time.time()
        }
    
    # Own send root
    own_send_root = {
        'root_secret': root_secret,
        'generation': 0,
        'last_used': time.time()
    }
    
    # Serialize tree for backup
    tree_serialized = base64.b64encode(tree.serialize()).decode('ascii')
    
    group_state = {
        'epoch': current_epoch,
        'tree': tree,
        'tree_serialized': tree_serialized,
        'epoch_secret': epoch_secret,
        'root_secret': root_secret,
        'group_id_b64': group_id_b64,
        'my_leaf_index': my_leaf_index,
        'my_user_id': my_user_id,
        'member_count': len(members),
        'cipher_suite': cipher_suite,
        'group_last_epoch': current_epoch,
        'joined_at': time.time(),
        'per_sender_roots': per_sender_roots,
        'own_send_root': own_send_root,
        'members_list': members,
        'final_secret': final_secret,  # Store final secrets per epoch for debugging
        # NEW: Track displayed messages
        'last_displayed_message_id': None,  # Last message ID shown to user
        'displayed_messages': []            # List of all displayed message IDs
    }
    
    print(f"✅ Initialized group state with message tracking")
    print(f"   Initial root_secret: {root_secret[:8].hex()}...")
    print(f"   Tracking {len(per_sender_roots)} senders")
    
    return group_state

@app.route('/api/messages/update-read-status', methods=['POST'])
def update_read_status():
    """Update the last displayed message ID for a group"""
    data = request.json
    group_id_b64 = data.get('group_id_b64')
    message_id = data.get('message_id')
    
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if user_id not in user_crypto_store:
        return jsonify({'error': 'User not found'}), 400
    
    if 'groups' not in user_crypto_store[user_id]:
        return jsonify({'error': 'No groups'}), 400
    
    if group_id_b64 not in user_crypto_store[user_id]['groups']:
        return jsonify({'error': 'Group not found'}), 404
    
    # Update the last displayed message ID
    user_crypto_store[user_id]['groups'][group_id_b64]['last_displayed_message_id'] = message_id
    
    # Add to displayed messages list if not already there
    if 'displayed_messages' not in user_crypto_store[user_id]['groups'][group_id_b64]:
        user_crypto_store[user_id]['groups'][group_id_b64]['displayed_messages'] = []
    
    if message_id not in user_crypto_store[user_id]['groups'][group_id_b64]['displayed_messages']:
        user_crypto_store[user_id]['groups'][group_id_b64]['displayed_messages'].append(message_id)
    
    return jsonify({'success': True})

if __name__ == '__main__': 
    app.run(debug=True, host='0.0.0.0', port=5000)

