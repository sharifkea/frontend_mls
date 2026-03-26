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
    
    sessionStorage.setItem('userId', userId);
    sessionStorage.setItem('token', token);
    sessionStorage.setItem('username', username);
}

async function loadSession() {
    const db = await initDB();
    const tx = db.transaction(STORES.SESSION, 'readonly');
    const store = tx.objectStore(STORES.SESSION);
    
    return new Promise((resolve) => {
        const request = store.get('current');
        request.onsuccess = () => resolve(request.result || null);
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
            await saveSession(data.user_id, data.token, data.username);
            
            document.getElementById('auth-container').style.display = 'none';
            document.getElementById('app-container').style.display = 'block';
            document.getElementById('user-display').textContent = data.username;
            
            initializeUI();
            await loadUserGroups(data.user_id, data.token);
            await checkForPendingWelcomes();
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

// ==================== MESSAGING ====================

window.selectedGroup = null;



function selectGroup(group) {
    console.log('📌 selectGroup called for group:', group.group_name);
    console.trace('selectGroup called from:');
    // Check if we're already viewing this group
    if (window.selectedGroup && window.selectedGroup.group_id === group.group_id) {
        console.log('Already viewing this group, skipping');
        return;
    }
    
    // Clear existing interval completely
    if (messageRefreshInterval) {
        clearInterval(messageRefreshInterval);
        messageRefreshInterval = null;
        console.log('🛑 Cleared existing message interval');
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
    
    // Load messages once immediately
    loadMessages(window.selectedGroup.group_id_hex);
    
    
    // TEMPORARILY DISABLE AUTO-REFRESH FOR DEBUGGING
    // messageRefreshInterval = setInterval(() => { ... }, 3000);
    
    console.log('Auto-refresh disabled for debugging');
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
        console.log(`📩 [${new Date().toLocaleTimeString()}] Fetching messages for group: ${groupIdHex}`);
        
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
                displayMessages(data.messages);
            }
        } else {
            console.error('Failed to load messages:', data.error);
        }
    } catch (error) {
        console.error('Failed to load messages:', error);
        if (container) {
            container.classList.remove('loading');
            container.innerHTML = '<div class="no-messages">Error loading messages</div>';
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
    
    container.innerHTML = '';
    
    if (!messages || messages.length === 0) {
        container.innerHTML = '<div class="no-messages">No messages yet</div>';
        return;
    }
    
    const currentUser = sessionStorage.getItem('username');
    
    messages.forEach(msg => {
        const isSelf = msg.sender_username === currentUser;
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isSelf ? 'sent' : 'received'}`;
        
        let timeStr = '';
        if (msg.created_at) {
            const date = new Date(msg.created_at);
            timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        
        messageDiv.innerHTML = `
            <div class="message-header">
                <span class="sender">${escapeHtml(msg.sender_username || 'Unknown')}</span>
                <span class="time">${timeStr}</span>
            </div>
            <div class="message-content">${escapeHtml(msg.text)}</div>
        `;
        
        container.appendChild(messageDiv);
    });
    
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
        const response = await fetch('/api/messages/send', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify({
                group_id_hex: window.selectedGroup.group_id_hex || base64ToHex(window.selectedGroup.group_id),
                message: messageText
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Failed to send message: ' + data.error);
        } else {
            document.getElementById('message-text').value = '';
            // Refresh messages immediately
            const groupIdHex = window.selectedGroup.group_id_hex || base64ToHex(window.selectedGroup.group_id);
            if (groupIdHex) {
                await loadMessages(groupIdHex);
            }
        }
    } catch (error) {
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

