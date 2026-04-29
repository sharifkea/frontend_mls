// static/js/app.js

// Database name and version
const DB_NAME = 'MLSMessengerDB';
const DB_VERSION = 1;

let welcomeCheckInterval = null;
let isCheckingWelcomes = false;
let isProcessingWelcome = false;
let pendingWelcomeQueue = [];
let currentGroupId = null;
let messageRefreshInterval = null;
let isRefreshing = false;
let refreshRequestCount = 0;
// static/js/app.js
let ws = null;
let wsReconnectInterval = null;
// Store names
const STORES = {
    SESSION: 'session',
    KEYS: 'keys',
    GROUPS: 'groups'
};

// ==================== UTILITY FUNCTIONS ====================

// Convert base64 to hex string
function base64ToHex(base64) {
    if (!base64) return null;
    try {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    } catch (e) {
        console.error('Failed to convert base64 to hex:', e);
        return null;
    }
}


// Replace your existing initWebSocket with this updated version
async function initWebSocket() {
    console.log('🔍 initWebSocket called');
    
    // Get session data
    let userId = sessionStorage.getItem('userId');
    let token = sessionStorage.getItem('token');
    let username = sessionStorage.getItem('username');
    
    if (!userId || !token) {
        const session = await loadSession();
        if (session) {
            userId = session.userId;
            token = session.token;
            username = session.username;
        }
    }
    
    console.log('🔍 userId:', userId);
    console.log('🔍 token exists:', !!token);
    
    if (!userId || !token) {
        console.log('❌ No valid session, WebSocket not initialized');
        return;
    }
    
    // Close existing connection
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close();
    }
    
    const wsUrl = `ws://localhost:8000/ws/${userId}?token=${token}&username=${encodeURIComponent(username)}`;
    console.log('🔌 Connecting WebSocket to:', wsUrl.substring(0, 100) + '...');
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('✅ WebSocket connected to FastAPI');
        if (wsReconnectInterval) {
            clearInterval(wsReconnectInterval);
            wsReconnectInterval = null;
        }
        // Start heartbeat
        startHeartbeat();
        // Get online users
        ws.send(JSON.stringify({ type: 'get_online_users' }));
    };
    
    ws.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);
            console.log('📨 WebSocket message type:', data.type);
            
            switch (data.type) {
                case 'new_message':
                    await handleIncomingMessage(data);
                    break;
                    
                case 'pong':
                    console.log('💓 Heartbeat received');
                    break;
                
                case 'refresh_messages':
                    console.log(`🔄 Refresh messages for group ${data.group_id_b64}`);
                    if (window.selectedGroup && window.selectedGroup.group_id === data.group_id_b64) {
                        // Reload messages for this group
                        loadMessages(window.selectedGroup.group_id_hex);
                    }
                    break;
                    
                case 'message_sent':
                    console.log('✅ Message delivery confirmed by server');
                    // Optional: show a small checkmark next to the message
                    break;
                    
                case 'user_online':
                    showToast(`${data.username} is now online`, 'info');
                    break;
                    
                case 'user_offline':
                    showToast(`${data.username} went offline`, 'info');
                    break;
                    
                case 'online_users':
                    console.log('Online users:', data.users);
                    break;
                    
                case 'joined':
                    console.log('Joined group:', data.group_id);
                    break;
                
                case 'join_request':
                    console.log(`📢 Join request from ${data.requester_username} for group "${data.group_name}"`);
                    console.log('Full data:', data);
                    
                    showNotification(`Join request from ${data.requester_username}`, 'info');
                    
                    if (confirm(`User ${data.requester_username} wants to join group "${data.group_name}". Accept?`)) {
                        console.log('✅ User accepted, sending add-member request...');
                        
                        const session = await loadSession();
                        console.log('Session loaded:', session?.userId);
                        
                        const requestBody = {
                            group_id: data.group_id,
                            new_user_id: data.requester_id,
                            new_username: data.requester_username
                        };
                        console.log('Request body:', requestBody);
                        
                        try {
                            const response = await fetch('/api/groups/add-member', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${session.token}`
                                },
                                body: JSON.stringify(requestBody)
                            });
                            
                            console.log('Response status:', response.status);
                            const result = await response.json();
                            console.log('Response data:', result);
                            
                            if (result.success) {
                                showToast(`Added ${data.requester_username} to group!`, 'success');
                                loadUserGroups(session.userId, session.token);
                            } else {
                                showToast(`Error: ${result.error}`, 'error');
                                console.error('Add member error:', result.error);
                            }
                        } catch (error) {
                            console.error('Fetch error:', error);
                            showToast(`Error: ${error.message}`, 'error');
                        }
                    } else {
                        console.log('❌ User rejected the join request');
                    }
                    break;


                case 'group_update':
                    console.log(`🔄 Group ${data.group_id} updated - new epoch: ${data.update_data.new_epoch}`);
                    console.log(`   New member: ${data.update_data.new_member.username}`);
                    
                    const session = await loadSession();
                    if (session) {
                        // Show notification
                        showToast(`Group updated! New member: ${data.update_data.new_member.username}`, 'info');
                        
                        // Refresh group state
                        const response = await fetch('/api/groups/update-state', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${session.token}`
                            },
                            body: JSON.stringify({
                                group_id: data.group_id,
                                update_data: data.update_data
                            })
                        });
                        
                        const result = await response.json();
                        if (result.success) {
                            console.log('✅ Group state updated successfully');
                            // Refresh groups list and messages
                            loadUserGroups(session.userId, session.token);
                            if (window.selectedGroup && window.selectedGroup.group_id === data.group_id) {
                                loadMessages(window.selectedGroup.group_id_hex);
                            }
                        }
                    }
                    break;

                case 'new_user_ready_to_join':
                    // Creator received notification about new user wanting to join
                    if (confirm(`User ${data.new_username} wants to join group "${data.group_name}". Add them?`)) {
                        // Call Flask endpoint to add member
                        fetch('/api/groups/add-member', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${session.token}`
                            },
                            body: JSON.stringify({
                                group_id: data.group_id,
                                new_user_id: data.new_user_id,
                                new_username: data.new_username
                            })
                        });
                    }
                    break;
                    
                default:
                    console.log('Unknown message type:', data.type);
            }
        } catch (e) {
            console.error('Failed to parse WebSocket message:', e);
        }
    };
    
    ws.onclose = () => {
        console.log('🔌 WebSocket disconnected');
        if (!wsReconnectInterval) {
            wsReconnectInterval = setInterval(() => {
                console.log('Attempting to reconnect WebSocket...');
                initWebSocket();
            }, 5000);
        }
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function startHeartbeat() {
    // Clear existing interval if any
    if (window.heartbeatInterval) {
        clearInterval(window.heartbeatInterval);
    }
    
    window.heartbeatInterval = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
            console.log('💓 Heartbeat sent');
        }
    }, 30000);
}

// Convert hex to base64
function hexToBase64(hex) {
    if (!hex) return null;
    try {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return btoa(String.fromCharCode.apply(null, bytes));
    } catch (e) {
        console.error('Failed to convert hex to base64:', e);
        return null;
    }
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== INDEXEDDB FUNCTIONS ====================

async function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            
            if (!db.objectStoreNames.contains(STORES.SESSION)) {
                db.createObjectStore(STORES.SESSION, { keyPath: 'id' });
            }
            
            if (!db.objectStoreNames.contains(STORES.KEYS)) {
                const keyStore = db.createObjectStore(STORES.KEYS, { keyPath: 'id' });
                keyStore.createIndex('userId', 'userId', { unique: false });
            }
            
            if (!db.objectStoreNames.contains(STORES.GROUPS)) {
                const groupStore = db.createObjectStore(STORES.GROUPS, { keyPath: 'groupId' });
                groupStore.createIndex('userId', 'userId', { unique: false });
            }
        };
    });
}

async function saveSession(userId, token, username) {
    if (!userId || typeof userId !== 'string') {
        console.error('Invalid userId for saveSession:', userId);
        return;
    }
    
    console.log('💾 Saving session for user:', userId);
    
    // 1. Save to sessionStorage (immediate, synchronous)
    sessionStorage.setItem('userId', userId);
    sessionStorage.setItem('token', token);
    sessionStorage.setItem('username', username);
    
    // 2. Save to IndexedDB (for persistence across sessions)
    const db = await initDB();
    const tx = db.transaction(STORES.SESSION, 'readwrite');
    const store = tx.objectStore(STORES.SESSION);
    
    await store.put({
        id: 'current',
        userId,
        token,
        username,
        timestamp: Date.now()
    });
    
    console.log('✅ Session saved to both storages');
}

async function loadSession() {
    // Try sessionStorage first (faster, synchronous)
    const userId = sessionStorage.getItem('userId');
    const token = sessionStorage.getItem('token');
    const username = sessionStorage.getItem('username');
    
    if (userId && token) {
        console.log('Session loaded from sessionStorage:', userId);
        return { userId, token, username };
    }
    
    // Fallback to IndexedDB
    console.log('Session not in sessionStorage, trying IndexedDB...');
    const db = await initDB();
    const tx = db.transaction(STORES.SESSION, 'readonly');
    const store = tx.objectStore(STORES.SESSION);
    
    return new Promise((resolve) => {
        const request = store.get('current');
        request.onsuccess = () => {
            const result = request.result;
            if (result) {
                // Cache to sessionStorage for next time
                sessionStorage.setItem('userId', result.userId);
                sessionStorage.setItem('token', result.token);
                sessionStorage.setItem('username', result.username);
                resolve(result);
            } else {
                resolve(null);
            }
        };
        request.onerror = () => resolve(null);
    });
}

async function clearSession() {
    const db = await initDB();
    const tx = db.transaction(STORES.SESSION, 'readwrite');
    const store = tx.objectStore(STORES.SESSION);
    
    await store.delete('current');
    sessionStorage.clear();
    
    await fetch('/api/logout', { method: 'POST' });
}

async function saveGroupsToDB(userId, groups) {
    if (!userId || typeof userId !== 'string') {
        console.error('Invalid userId for saveGroupsToDB:', userId);
        return;
    }
    
    try {
        const db = await initDB();
        const tx = db.transaction(STORES.GROUPS, 'readwrite');
        const store = tx.objectStore(STORES.GROUPS);
        
        // Clear old groups for this user
        const index = store.index('userId');
        const range = IDBKeyRange.only(userId);
        
        index.openCursor(range).onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                cursor.delete();
                cursor.continue();
            }
        };
        
        // Save new groups
        groups.forEach(group => {
            if (group.group_id) {
                store.put({
                    ...group,
                    groupId: group.group_id,
                    userId: userId
                });
            }
        });
        
        console.log(`✅ Saved ${groups.length} groups to IndexedDB`);
    } catch (error) {
        console.error('Failed to save groups to IndexedDB:', error);
    }
}

async function loadGroupsFromDB(userId) {
    if (!userId || typeof userId !== 'string') {
        console.error('Invalid userId for loadGroupsFromDB:', userId);
        return [];
    }
    
    try {
        const db = await initDB();
        const tx = db.transaction(STORES.GROUPS, 'readonly');
        const store = tx.objectStore(STORES.GROUPS);
        const index = store.index('userId');
        
        return new Promise((resolve) => {
            const request = index.getAll(IDBKeyRange.only(userId));
            request.onsuccess = () => resolve(request.result || []);
            request.onerror = () => resolve([]);
        });
    } catch (error) {
        console.error('Failed to load groups from IndexedDB:', error);
        return [];
    }
}

// ==================== AUTHENTICATION ====================

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.auth-form').forEach(form => form.classList.remove('active'));
    
    if (tab === 'login') {
        document.querySelector('[onclick="switchTab(\'login\')"]').classList.add('active');
        document.getElementById('login-form').classList.add('active');
    } else {
        document.querySelector('[onclick="switchTab(\'register\')"]').classList.add('active');
        document.getElementById('register-form').classList.add('active');
    }
}

async function handleRegister() {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;
    const errorDiv = document.getElementById('register-error');
    
    if (!username || !password) {
        errorDiv.textContent = 'Username and password required';
        return;
    }
    
    if (password !== confirm) {
        errorDiv.textContent = 'Passwords do not match';
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.error) {
            errorDiv.textContent = data.error;
        } else {
            errorDiv.textContent = 'Registration successful! Please login.';
            document.getElementById('register-username').value = '';
            document.getElementById('register-password').value = '';
            document.getElementById('register-confirm').value = '';
            switchTab('login');
        }
    } catch (error) {
        errorDiv.textContent = 'Network error';
    }
}

async function handleLogin() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorDiv = document.getElementById('login-error');
    
    if (!username || !password) {
        errorDiv.textContent = 'Username and password required';
        return;
    }
    
    try {
        console.log('Logging in...');
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        console.log('Login response:', data);
        
        if (!response.ok) {
            errorDiv.textContent = data.error || 'Login failed';
            return;
        }
        
        if (data.error) {
            errorDiv.textContent = data.error;
        } else {
            // Save session to both storage types
            await saveSession(data.user_id, data.token, data.username);
            
            // CRITICAL: Add a small delay to ensure IndexedDB write completes
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Verify session was saved
            const testSession = await loadSession();
            console.log('Session after save:', testSession);
            
            // Only proceed if session is valid
            if (!testSession || !testSession.userId) {
                console.error('Session verification failed!');
                errorDiv.textContent = 'Session error. Please try again.';
                return;
            }
            
            // Update UI first
            document.getElementById('auth-container').style.display = 'none';
            document.getElementById('app-container').style.display = 'block';
            document.getElementById('user-display').textContent = data.username;
            
            initializeUI();
            
            // Initialize WebSocket AFTER UI is ready and session is confirmed
            initWebSocket();
            // Load data
            await loadUserGroups(data.user_id, data.token);
            await checkForPendingWelcomes();
            //await restoreGroupStates(data.user_id, data.token);
        }
    } catch (error) {
        console.error('Login error:', error);
        errorDiv.textContent = 'Network error';
    }
}

// ==================== GROUP MANAGEMENT ====================

async function loadUserGroups(userId, token) {
    if (!userId || typeof userId !== 'string') {
        console.error('Invalid userId for loadUserGroups:', userId);
        displayGroups([]);
        return;
    }
    
    try {
        console.log('📡 Loading groups for user:', userId);
        
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to load groups: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('📥 Groups response:', data);
        
        let groups = [];
        if (data.success && data.groups) {
            groups = data.groups;
        } else if (data.groups) {
            groups = data.groups;
        } else if (Array.isArray(data)) {
            groups = data;
        }
        
        console.log(`✅ Found ${groups.length} groups`);
        displayGroups(groups);
        await saveGroupsToDB(userId, groups);
        
    } catch (error) {
        console.error('❌ Failed to load groups:', error);
        const offlineGroups = await loadGroupsFromDB(userId);
        if (offlineGroups && offlineGroups.length > 0) {
            console.log(`📦 Loaded ${offlineGroups.length} groups from IndexedDB`);
            displayGroups(offlineGroups);
        } else {
            displayGroups([]);
        }
    }
}

function displayGroups(groups) {
    const groupsList = document.getElementById('groups-list');
    if (!groupsList) return;
    
    groupsList.innerHTML = '';
    
    if (groups.length === 0) {
        groupsList.innerHTML = '<div class="no-groups">No groups yet. Create one!</div>';
        return;
    }
    
    groups.forEach(group => {
        const groupIdB64 = group.group_id;
        const groupIdHex = base64ToHex(groupIdB64) || groupIdB64;
        
        const groupEl = document.createElement('div');
        groupEl.className = 'group-item';
        groupEl.dataset.groupIdB64 = groupIdB64;
        groupEl.dataset.groupIdHex = groupIdHex;
        groupEl.innerHTML = `
            <div class="group-name">${escapeHtml(group.group_name || 'Unnamed Group')}</div>
            <div class="group-meta">
                <span>${group.member_count || 1} members</span>
                <span>Epoch: ${group.epoch || 0}</span>
            </div>
            <div class="group-id">ID: ${groupIdHex.substring(0, 8)}...</div>
        `;
        
        groupEl.onclick = () => {
            selectGroup({
                ...group,
                group_id_hex: groupIdHex,
                group_id: groupIdB64
            });
        };
        
        groupsList.appendChild(groupEl);
    });
}

async function restoreGroupStates(userId, token) {
    console.log('🔄 Restoring group states...');
    
    try {
        const response = await fetch('/api/groups/restore-states', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ user_id: userId })
        });
        
        const data = await response.json();
        
        if (data.success) {
            console.log(`✅ Restored ${data.restored_count} group states`);
        } else {
            console.error('Failed to restore group states:', data.error);
        }
    } catch (error) {
        console.error('Error restoring group states:', error);
    }
}

// ==================== MESSAGING ====================

window.selectedGroup = null;



function selectGroup(group) {
    console.log('📌 selectGroup called for group:', group.group_name);
    
    // Check if we're already viewing this group
    if (window.selectedGroup && window.selectedGroup.group_id === group.group_id) {
        console.log('Already viewing this group, skipping');
        return;
    }
    
    // Clear existing interval
    if (messageRefreshInterval) {
        clearInterval(messageRefreshInterval);
        messageRefreshInterval = null;
    }
    
    // Reset flags
    isRefreshing = false;
    refreshRequestCount = 0;
    
    // Store the new group
    window.selectedGroup = {
        ...group,
        group_id_hex: group.group_id_hex || base64ToHex(group.group_id)
    };
    currentGroupId = window.selectedGroup.group_id;
    
    // Update UI
    document.getElementById('group-name').textContent = group.group_name || 'Selected Group';
    document.getElementById('message-text').disabled = false;
    document.getElementById('send-btn').disabled = false;
    
    // ✅ CLEAR the message container when switching groups
    const container = document.getElementById('messages-container');
    if (container) {
        container.innerHTML = '<div class="no-messages">Loading messages...</div>';
    }
    
    // Load messages for this group
    loadMessages(window.selectedGroup.group_id_hex);
}

async function loadMessages(groupIdHex) {
    // Prevent multiple simultaneous calls
    if (isRefreshing) {
        console.log('⏸️ Load already in progress, skipping');
        return;
    }
    
    isRefreshing = true;
    
    const session = await loadSession();
    if (!session) {
        isRefreshing = false;
        return;
    }
    
    const container = document.getElementById('messages-container');
    if (container) {
        container.classList.add('loading');
    }
    
    try {
        console.log(`📩 Fetching new messages for group: ${groupIdHex}`);
        
        const response = await fetch('/api/messages/get', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify({
                group_id_hex: groupIdHex
            })
        });
        
        const data = await response.json();
        
        if (container) {
            container.classList.remove('loading');
        }
        
        if (data.success) {
            // Only update if we're still on the same group
            if (window.selectedGroup && window.selectedGroup.group_id_hex === groupIdHex) {
                // ✅ This will APPEND new messages, not replace all
                displayMessages(data.messages);
            }
        } else {
            console.error('Failed to load messages:', data.error);
        }
    } catch (error) {
        console.error('Failed to load messages:', error);
        if (container) {
            container.classList.remove('loading');
            if (container.children.length === 0) {
                container.innerHTML = '<div class="no-messages">Error loading messages</div>';
            }
        }
    } finally {
        isRefreshing = false;
    }
}

// Also update handleLogout to clear everything
async function handleLogout() {
    // Stop all intervals
    if (messageRefreshInterval) {
        clearInterval(messageRefreshInterval);
        messageRefreshInterval = null;
    }
    
    stopWelcomePolling();
    
    await clearSession();
    
    // Reset all flags
    isRefreshing = false;
    refreshRequestCount = 0;
    currentGroupId = null;
    window.selectedGroup = null;
    
    document.getElementById('auth-container').style.display = 'block';
    document.getElementById('app-container').style.display = 'none';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('login-error').textContent = '';
}

function stopMessagePolling() {
    if (messageRefreshInterval) {
        clearInterval(messageRefreshInterval);
        messageRefreshInterval = null;
        console.log('🛑 Stopped message polling');
    }
}

// Initialize the loading flag
loadMessages.isLoading = false;

function displayMessages(messages) {
    const container = document.getElementById('messages-container');
    if (!container) return;
    
    console.log('📊 displayMessages called with', messages.length, 'messages');
    console.log('📊 Current container has', container.children.length, 'children');
    
    // If this is the first load (container is empty or has "no messages"), clear it
    const isEmpty = container.children.length === 0 || 
                    (container.children.length === 1 && container.querySelector('.no-messages'));
    
    console.log('📊 isEmpty:', isEmpty);
    
    if (isEmpty) {
        console.log('📊 Clearing container for first load');
        container.innerHTML = '';
    }
    
    if (!messages || messages.length === 0) {
        if (container.children.length === 0) {
            container.innerHTML = '<div class="no-messages">No messages yet</div>';
        }
        return;
    }
    
    const currentUser = sessionStorage.getItem('username');
    let addedCount = 0;
    
    messages.forEach(msg => {
        // Check if message already exists in UI (by message_id)
        const existingMessage = document.querySelector(`.message[data-message-id="${msg.message_id}"]`);
        if (existingMessage) {
            console.log('⏭️ Skipping duplicate message:', msg.message_id);
            return;
        }
        
        const isSelf = msg.sender_username === currentUser;
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isSelf ? 'sent' : 'received'}`;
        messageDiv.setAttribute('data-message-id', msg.message_id || Date.now());
        
        let timeStr = '';
        if (msg.created_at) {
            const date = new Date(msg.created_at);
            timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else {
            timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        
        messageDiv.innerHTML = `
            <div class="message-header">
                <span class="sender">${escapeHtml(msg.sender_username || 'Unknown')}</span>
                <span class="time">${timeStr}</span>
            </div>
            <div class="message-content">${escapeHtml(msg.text)}</div>
        `;
        
        container.appendChild(messageDiv);
        addedCount++;
    });
    
    console.log('📊 Added', addedCount, 'new messages');
    
    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
    const session = await loadSession();
    if (!session) return;
    
    const messageText = document.getElementById('message-text').value;
    if (!messageText.trim()) return;
    
    if (!window.selectedGroup) {
        alert('Select a group first');
        return;
    }
    
    try {
        // Use your EXISTING working endpoint
        const response = await fetch('/api/messages/send', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify({
                group_id_hex: window.selectedGroup.group_id_hex,
                message: messageText
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Failed to send message: ' + data.error);
            return;
        }
        
        // Clear input
        document.getElementById('message-text').value = '';
        
        // Display own message immediately
        appendMessageToUI({
            sender_username: session.username,
            text: messageText,
            created_at: new Date().toISOString()
        });
        
        // Send WebSocket notification to others (just the notification, not the encrypted message)
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: "new_message_notification",
                group_id_b64: window.selectedGroup.group_id,
                sender_username: session.username
            }));
            console.log('📡 WebSocket notification sent');
        }
        
    } catch (error) {
        console.error('Error sending message:', error);
        alert('Error: ' + error.message);
    }
}

// ==================== WELCOME MESSAGES ====================

async function checkForPendingWelcomes() {
    const session = await loadSession();
    if (!session) return;
    
    if (isProcessingWelcome) {
        console.log('⏳ Already processing welcomes, skipping check');
        return;
    }
    
    try {
        console.log('📨 Checking for pending welcome messages...');
        
        const response = await fetch('/api/welcomes/pending', {
            headers: { 'Authorization': `Bearer ${session.token}` }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch welcomes');
        }
        
        const data = await response.json();
        
        if (data.success && data.welcomes && data.welcomes.length > 0) {
            console.log(`🎉 You have ${data.welcomes.length} new group invitation(s)!`);
            showNotification(`You have ${data.welcomes.length} new group invitation(s)!`, 'info');
            
            for (const welcome of data.welcomes) {
                await processWelcome(welcome, session.token);
            }
        }
    } catch (error) {
        console.error('Error checking welcomes:', error);
    }
}

async function processWelcome(welcome, token) {
    if (isProcessingWelcome) {
        console.log(`⏳ Welcome ${welcome.id} queued (already processing another)`);
        pendingWelcomeQueue.push({ welcome, token });
        return false;
    }
    
    isProcessingWelcome = true;
    
    try {
        console.log(`🔐 Processing welcome for group: ${welcome.group_id}`);
        
        const response = await fetch('/api/welcomes/process', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                welcome_b64: welcome.welcome_b64,
                group_id: welcome.group_id,
                welcome_id: welcome.id
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            console.log(`✅ Successfully joined group: ${data.group_id}`);
            showToast(`Joined new group!`, 'success');
            
            const session = await loadSession();
            if (session) {
                await loadUserGroups(session.userId, session.token);
            }
            return true;
        } else {
            console.error('Failed to join group:', data.error);
            showToast(`Failed to join group: ${data.error}`, 'error');
            return false;
        }
    } catch (error) {
        console.error('Error processing welcome:', error);
        return false;
    } finally {
        isProcessingWelcome = false;
        
        if (pendingWelcomeQueue.length > 0) {
            const next = pendingWelcomeQueue.shift();
            console.log(`🔄 Processing next queued welcome`);
            processWelcome(next.welcome, next.token);
        }
    }
}

// ==================== GROUP CREATION ====================

async function createGroupWithOnline() {
    const session = await loadSession();
    if (!session) {
        alert('Please login first');
        return;
    }
    
    const groupName = prompt('Enter group name:', 'MLS Test Group');
    if (!groupName) return;
    
    try {
        const onlineResponse = await fetch('/api/online-users');
        const onlineData = await onlineResponse.json();
        
        if (onlineData.count < 1) {
            alert('No other users online to add to group');
            return;
        }
        
        console.log(`Found ${onlineData.count} online users:`, onlineData.users);
        
        const response = await fetch('/api/groups/create-with-online', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ group_name: groupName, users: onlineData.users })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Failed to create group: ' + data.error);
        } else {
            alert(`✅ Group "${groupName}" created with ${data.member_count} members!`);
            await loadUserGroups(session.user_id, session.token);
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// ==================== UI HELPERS ====================

function showNotification(message, type = 'info') {
    console.log(`🔔 [${type}] ${message}`);
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px;
        background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};
        color: white;
        border-radius: 5px;
        z-index: 1000;
        animation: slideInRight 0.3s ease;
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 20px;
        background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};
        color: white;
        border-radius: 4px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        z-index: 1000;
        animation: slideInRight 0.3s ease, fadeOut 0.3s ease 2.7s forwards;
        font-size: 14px;
    `;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        if (toast.parentNode) toast.remove();
    }, 3000);
}

function addRefreshButton() {
    const groupsSection = document.querySelector('.groups-section h3');
    if (groupsSection && !document.getElementById('refresh-groups-btn')) {
        const refreshBtn = document.createElement('button');
        refreshBtn.id = 'refresh-groups-btn';
        refreshBtn.innerHTML = '↻';
        refreshBtn.title = 'Refresh groups';
        refreshBtn.style.cssText = `
            float: right;
            background: none;
            border: none;
            font-size: 18px;
            cursor: pointer;
            color: #667eea;
            padding: 0 5px;
        `;
        refreshBtn.onclick = async () => {
            const session = await loadSession();
            if (session) {
                await checkForPendingWelcomes();
                await loadUserGroups(session.userId, session.token);
            }
        };
        groupsSection.appendChild(refreshBtn);
    }
}

function initializeUI() {
    addRefreshButton();
}

function startWelcomePolling(intervalSeconds = 30) {
    if (welcomeCheckInterval) clearInterval(welcomeCheckInterval);
    
    console.log(`🕒 Starting welcome polling every ${intervalSeconds} seconds`);
    welcomeCheckInterval = setInterval(async () => {
        if (!isCheckingWelcomes && !isProcessingWelcome) {
            isCheckingWelcomes = true;
            try {
                await checkForPendingWelcomes();
            } catch (error) {
                console.error('Error in welcome polling:', error);
            } finally {
                isCheckingWelcomes = false;
            }
        }
    }, intervalSeconds * 1000);
}

function stopWelcomePolling() {
    if (welcomeCheckInterval) {
        clearInterval(welcomeCheckInterval);
        welcomeCheckInterval = null;
        console.log('🛑 Stopped welcome polling');
    }
}

// Search for and join a group
async function searchAndJoinGroup() {
    const session = await loadSession();
    if (!session) {
        alert('Please login first');
        return;
    }
    
    const groupName = prompt('Enter group name to search:', 'MLS Test Group');
    if (!groupName) return;
    
    try {
        showToast('Searching for group...', 'info');
        
        // Call Flask endpoint (same origin, no CORS issue)
        const response = await fetch(`/api/groups/search?group_name=${encodeURIComponent(groupName)}`, {
            headers: { 'Authorization': `Bearer ${session.token}` }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Search results:', data);
        
        if (!data.groups || data.groups.length === 0) {
            showToast(`No group found with name "${groupName}"`, 'error');
            return;
        }
        
        const group = data.groups[0];
        
        if (confirm(`Do you want to request to join "${group.group_name}"?\n\nCreator: ${group.creator_username}\nMembers: ${group.member_count}`)) {
            await sendJoinRequest(group, session.token);
        }
        
    } catch (error) {
        console.error('Error searching group:', error);
        showToast('Error searching for group: ' + error.message, 'error');
    }
}

async function sendJoinRequest(group, token) {
    try {
        // Call Flask endpoint to request join
        const response = await fetch('/api/groups/request-join', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                group_id: group.group_id,
                group_name: group.group_name
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`Join request sent to ${group.creator_username}!`, 'success');
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error sending join request:', error);
        showToast('Error sending join request', 'error');
    }
}

async function handleIncomingMessage(data) {
    console.log(`📩 Real-time message from ${data.sender_username}`);
    
    if (window.selectedGroup && window.selectedGroup.group_id === data.group_id_b64) {
        const session = await loadSession();
        if (session) {
            const decrypted = await decryptSingleMessage(data, session.token);
            if (decrypted) {
                appendMessageToUI(decrypted);
                
                // Also update the last displayed message ID in session
                await updateLastDisplayedMessage(data.group_id_b64, decrypted.message_id);
            }
        }
    } else {
        showNotification(`New message from ${data.sender_username}`, 'info');
        markGroupUnread(data.group_id_b64);
    }
}

// New function to update last displayed message ID
async function updateLastDisplayedMessage(groupIdB64, messageId) {
    const session = await loadSession();
    if (!session) return;
    
    try {
        await fetch('/api/messages/update-read-status', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify({
                group_id_b64: groupIdB64,
                message_id: messageId
            })
        });
    } catch (error) {
        console.error('Failed to update read status:', error);
    }
}


// ==================== WINDOW EVENT HANDLERS ====================

window.addEventListener('focus', async () => {
    const session = await loadSession();
    if (session) {
        console.log('🖥️ Window focused, refreshing...');
        await checkForPendingWelcomes();
        await loadUserGroups(session.userId, session.token);
    }
});

window.addEventListener('load', async () => {
    const session = await loadSession();
    if (session) {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').style.display = 'block';
        document.getElementById('user-display').textContent = session.username;
        initializeUI();
        await loadUserGroups(session.userId, session.token);
        await checkForPendingWelcomes();
    }
});

// This is for real-time WebSocket messages
function appendMessageToUI(message) {
    const container = document.getElementById('messages-container');
    if (!container) return;
    
    // Remove "no messages" placeholder if it exists
    const noMessages = container.querySelector('.no-messages');
    if (noMessages) {
        noMessages.remove();
    }
    
    // Check if message already exists (prevent duplicates)
    if (message.message_id) {
        const existing = container.querySelector(`.message[data-message-id="${message.message_id}"]`);
        if (existing) {
            console.log('Message already displayed, skipping');
            return;
        }
    }
    
    const currentUser = sessionStorage.getItem('username');
    const isSelf = message.sender_username === currentUser;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isSelf ? 'sent' : 'received'}`;
    if (message.message_id) {
        messageDiv.setAttribute('data-message-id', message.message_id);
    }
    
    let timeStr = '';
    if (message.created_at) {
        const date = new Date(message.created_at);
        timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
        timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    messageDiv.innerHTML = `
        <div class="message-header">
            <span class="sender">${escapeHtml(message.sender_username)}</span>
            <span class="time">${timeStr}</span>
        </div>
        <div class="message-content">${escapeHtml(message.text)}</div>
    `;
    
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
    
    console.log(`✅ Appended message from ${message.sender_username}`);
}

