// static/js/app.js

// Database name and version
const DB_NAME = 'MLSMessengerDB';
const DB_VERSION = 1;

let welcomeCheckInterval = null;
let isCheckingWelcomes = false;

// Store names
const STORES = {
    SESSION: 'session',
    KEYS: 'keys',
    GROUPS: 'groups'
};

// Initialize IndexedDB
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

// Save session data
async function saveSession(userId, token, username) {
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

// Load session
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

// Clear session
async function clearSession() {
    const db = await initDB();
    const tx = db.transaction(STORES.SESSION, 'readwrite');
    const store = tx.objectStore(STORES.SESSION);
    
    await store.delete('current');
    sessionStorage.clear();
    
    await fetch('/api/logout', { method: 'POST' });
}

// Tab switching
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

// Handle Registration
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
        // Register with backend
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

// Handle Login
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
            // Save session
            await saveSession(data.user_id, data.token, data.username);
            
            // Show main app
            document.getElementById('auth-container').style.display = 'none';
            document.getElementById('app-container').style.display = 'block';
            document.getElementById('user-display').textContent = data.username;

            // INITIALIZE UI COMPONENTS AND EVENT LISTENERS
            initializeUI(); 
            
            // Load user's groups
            await loadUserGroups(data.user_id, data.token);
            
            // CHECK FOR PENDING WELCOMES AFTER LOGIN
            await checkForPendingWelcomes();
            
            // START PERIODIC WELCOME CHECKING (every 30 seconds)
            startWelcomePolling();
        }
    } catch (error) {
        console.error('Login error:', error);
        errorDiv.textContent = 'Network error';
    }
}
// Generate key package for user
async function generateUserKeyPackage(username) {
    try {
        const response = await fetch('/api/crypto/generate-keypackage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const data = await response.json();
        
        if (!data.success) {
            console.error('Failed to generate key package:', data.error);
        } else {
            console.log('Key package generated successfully');
            // Store key package reference in session
            sessionStorage.setItem('hasKeyPackage', 'true');
        }
    } catch (error) {
        console.error('Error generating key package:', error);
    }
}

// Handle Logout
async function handleLogout() {
    // Stop welcome polling
    stopWelcomePolling();
    
    await clearSession();
    
    document.getElementById('auth-container').style.display = 'block';
    document.getElementById('app-container').style.display = 'none';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('login-error').textContent = '';
}


// Create new group
async function createGroup() {
    const session = await loadSession();
    if (!session) {
        alert('Please login first');
        return;
    }
    
    const groupName = prompt('Enter group name:', 'New Group');
    if (!groupName) return;
    
    try {
        // First, generate key package if needed
        if (!sessionStorage.getItem('hasKeyPackage')) {
            console.log('Generating key package for user...', session.username);
            await generateUserKeyPackage(session.username);
        }
        
        // Get the key package (in real app, you'd store it)
        const keyPackageResponse = await fetch('/api/crypto/generate-keypackage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: session.username })
        });
        
        const keyPackageData = await keyPackageResponse.json();
        
        if (!keyPackageData.success) {
            alert('Failed to get key package');
            return;
        }
        
        // Create group on server
        const groupResponse = await fetch('/api/crypto/create-empty-group', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: session.username,
                key_package: keyPackageData.key_package
            })
        });
        
        const groupData = await groupResponse.json();
        
        if (!groupData.success) {
            alert('Failed to create group: ' + groupData.error);
            return;
        }
        
        // Save group metadata to database
        const saveResponse = await fetch('/api/groups', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify({
                group_name: groupName,
                group_id: groupData.group_id,
                cipher_suite: 1
            })
        });
        
        const saveData = await saveResponse.json();
        
        if (saveData.error) {
            alert('Error saving group: ' + saveData.error);
        } else {
            alert(`Group "${groupName}" created successfully!`);
            loadUserGroups(session.userId, session.token);
        }
    } catch (error) {
        alert('Error creating group: ' + error.message);
        console.error(error);
    }
}

// Load user's groups
async function loadUserGroups(userId, token) {
    try {
        console.log('📡 Loading groups for user:', userId);
        
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ Groups response not OK:', response.status, errorText);
            throw new Error(`Failed to load groups: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('📥 Groups response:', data);
        
        // Check the response structure from your Flask endpoint
        if (data.success && data.groups) {
            // ✅ Success - we have groups
            console.log(`✅ Found ${data.groups.length} groups`);
            displayGroups(data.groups);
            saveGroupsToDB(userId, data.groups);
        } else if (data.groups) {
            // Some endpoints return groups directly without success flag
            console.log(`✅ Found ${data.groups.length} groups (direct format)`);
            displayGroups(data.groups);
            saveGroupsToDB(userId, data.groups);
        } else if (Array.isArray(data)) {
            // If the response is directly an array
            console.log(`✅ Found ${data.length} groups (array format)`);
            displayGroups(data);
            saveGroupsToDB(userId, data);
        } else {
            // No groups found or unexpected format
            console.log('⚠️ No groups found or unexpected format:', data);
            displayGroups([]);
            saveGroupsToDB(userId, []);
        }
        
    } catch (error) {
        console.error('❌ Failed to load groups:', error);
        // Try to load from IndexedDB as fallback
        const offlineGroups = await loadGroupsFromDB(userId);
        if (offlineGroups && offlineGroups.length > 0) {
            console.log(`📦 Loaded ${offlineGroups.length} groups from IndexedDB`);
            displayGroups(offlineGroups);
        } else {
            displayGroups([]);
        }
    }
}

// Display groups
function displayGroups(groups) {
    const groupsList = document.getElementById('groups-list');
    groupsList.innerHTML = '';
    
    if (groups.length === 0) {
        groupsList.innerHTML = '<div class="no-groups">No groups yet. Create one!</div>';
        return;
    }
    
    groups.forEach(group => {
        const groupEl = document.createElement('div');
        groupEl.className = 'group-item';
        groupEl.innerHTML = `
            <div class="group-name">${group.group_name || 'Unnamed Group'}</div>
            <div class="group-meta">
                <span>${group.member_count || 1} members</span>
                <span>Epoch: ${group.epoch || 0}</span>
            </div>
            <div class="group-id">ID: ${group.group_id.substring(0, 8)}...</div>
        `;
        groupEl.onclick = () => selectGroup(group);
        groupsList.appendChild(groupEl);
    });
}

// Save groups to IndexedDB
async function saveGroupsToDB(userId, groups) {
    const db = await initDB();
    const tx = db.transaction(STORES.GROUPS, 'readwrite');
    const store = tx.objectStore(STORES.GROUPS);
    
    const index = store.index('userId');
    const range = IDBKeyRange.only(userId);
    index.openCursor(range).onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
            cursor.delete();
            cursor.continue();
        }
    };
    
    groups.forEach(group => {
        store.put({
            ...group,
            userId: userId
        });
    });
}

// Load groups from IndexedDB
async function loadGroupsFromDB(userId) {
    const db = await initDB();
    const tx = db.transaction(STORES.GROUPS, 'readonly');
    const store = tx.objectStore(STORES.GROUPS);
    const index = store.index('userId');
    
    return new Promise((resolve) => {
        const request = index.getAll(IDBKeyRange.only(userId));
        request.onsuccess = () => {
            displayGroups(request.result);
            resolve(request.result);
        };
        request.onerror = () => resolve([]);
    });
}

// Select a group
window.selectedGroup = null;
function selectGroup(group) {
    window.selectedGroup = group;
    document.getElementById('group-name').textContent = group.group_name || 'Selected Group';
    document.getElementById('message-text').disabled = false;
    document.getElementById('send-btn').disabled = false;
    
    // Load messages for this group
    loadMessages(group.group_id);
}

// Load messages
async function loadMessages(groupId) {
    const session = await loadSession();
    if (!session) return;
    
    try {
        const response = await fetch(`/api/messages/${groupId}`, {
            headers: { 'Authorization': `Bearer ${session.token}` }
        });
        
        const data = await response.json();
        displayMessages(data.messages || []);
    } catch (error) {
        console.error('Failed to load messages:', error);
    }
}

// Display messages
function displayMessages(messages) {
    const container = document.getElementById('messages-container');
    container.innerHTML = '';
    
    messages.forEach(msg => {
        displayMessage({
            text: '[Encrypted Message]', // Would decrypt here
            sender: msg.sender_username,
            isSelf: false
        });
    });
}

// Send message
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
        // Encrypt message via backend
        const encryptResponse = await fetch('/api/crypto/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                group_id: window.selectedGroup.group_id,
                message: messageText
            })
        });
        
        const encryptData = await encryptResponse.json();
        
        if (!encryptData.success) {
            alert('Encryption failed: ' + encryptData.error);
            return;
        }
        
        // Send encrypted message
        const sendResponse = await fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify({
                group_id: window.selectedGroup.group_id,
                ciphertext: encryptData.ciphertext,
                nonce: encryptData.nonce,
                epoch: window.selectedGroup.epoch || 1
            })
        });
        
        if (!sendResponse.ok) {
            throw new Error('Failed to send message');
        }
        
        // Display message locally
        displayMessage({
            text: messageText,
            sender: session.username,
            isSelf: true
        });
        
        document.getElementById('message-text').value = '';
        
    } catch (error) {
        alert('Failed to send message: ' + error.message);
    }
}

// Display a single message
function displayMessage(msg) {
    const container = document.getElementById('messages-container');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${msg.isSelf ? 'sent' : 'received'}`;
    
    messageDiv.innerHTML = `
        <div class="message-header">
            ${msg.isSelf ? 'You' : msg.sender}
        </div>
        <div class="message-content">${msg.text}</div>
    `;
    
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

async function createGroupWithOnline() {
    const session = await loadSession();
    if (!session) {
        alert('Please login first');
        return;
    }
    
    const groupName = prompt('Enter group name:', 'MLS Test Group');
    if (!groupName) return;
    
    try {
        // First, get list of online users
        const onlineResponse = await fetch('/api/online-users');
        const onlineData = await onlineResponse.json();
        
        if (onlineData.count < 1) {
            alert('No other users online to add to group');
            return;
        }
        
        console.log(`Found ${onlineData.count} online users:`, onlineData.users);
        
        // Create group with all online users
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
            loadUserGroups(session.user_id, session.token);
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Simple notification function
function showNotification(message, type = 'info') {
    // You can implement this as a toast or alert
    // For now, just console.log
    console.log(`🔔 [${type}] ${message}`);
    
    // Optional: Create a temporary div notification
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px;
        background: ${type === 'success' ? '#4CAF50' : '#2196F3'};
        color: white;
        border-radius: 5px;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Start periodic welcome checking
function startWelcomePolling(intervalSeconds = 30) {
    if (welcomeCheckInterval) {
        clearInterval(welcomeCheckInterval);
    }
    
    console.log(`🕒 Starting welcome polling every ${intervalSeconds} seconds`);
    welcomeCheckInterval = setInterval(async () => {
        if (!isCheckingWelcomes) {
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

// Stop welcome polling
function stopWelcomePolling() {
    if (welcomeCheckInterval) {
        clearInterval(welcomeCheckInterval);
        welcomeCheckInterval = null;
        console.log('🛑 Stopped welcome polling');
    }
}

// Enhanced checkForPendingWelcomes function
async function checkForPendingWelcomes() {
    const session = await loadSession();
    if (!session) return;
    
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
            
            // Show notification with count
            showNotification(`You have ${data.welcomes.length} new group invitation(s)!`, 'info');
            
            // Process each welcome
            let joinedCount = 0;
            for (const welcome of data.welcomes) {
                const success = await processWelcome(welcome, session.token);
                if (success) joinedCount++;
            }
            
            // If any welcomes were processed successfully, refresh the groups list
            if (joinedCount > 0) {
                console.log(`✅ Successfully joined ${joinedCount} new groups`);
                showNotification(`Joined ${joinedCount} new group(s)!`, 'success');
                await loadUserGroups(session.user_id, session.token);
            }
        }
    } catch (error) {
        console.error('Error checking welcomes:', error);
    }
}

// Enhanced processWelcome function
async function processWelcome(welcome, token) {
    try {
        console.log('Processing welcome for group:', welcome.group_id);
        
        const response = await fetch('/api/welcomes/process', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                welcome_b64: welcome.welcome_b64,
                group_id: welcome.group_id
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            console.log(`✅ Successfully joined group: ${data.group_id}`);
            
            // Show a small toast notification for this group
            showToast(`Joined new group!`, 'success');
            // Refresh group list
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
    }
}

// Toast notification function (smaller than notification)
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    // Style the toast
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
    
    // Remove after 3 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 3000);
}

// Also check for welcomes when window gains focus (user returns to tab)
window.addEventListener('focus', async () => {
    const session = await loadSession();
    if (session) {
        console.log('🖥️ Window focused, checking for welcomes...');
        await checkForPendingWelcomes();
        await loadUserGroups(session.user_id, session.token);
    }
});

// Add a manual refresh button to the groups section
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
                await loadUserGroups(session.user_id, session.token);
            }
        };
        groupsSection.appendChild(refreshBtn);
    }
}

// Call this after login
function initializeUI() {
    addRefreshButton();
}


// Check for existing session on page load
window.addEventListener('load', async () => {
    const session = await loadSession();
    if (session) {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').style.display = 'block';
        document.getElementById('user-display').textContent = session.username;
        loadUserGroups(session.userId, session.token);
    }
});