// static/js/app.js

// Database name and version
const DB_NAME = 'MLSMessengerDB';
const DB_VERSION = 1;

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
            
            // Create stores if they don't exist
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

// Save session data to IndexedDB
async function saveSession(userId, token, privateKey = null) {
    const db = await initDB();
    const tx = db.transaction(STORES.SESSION, 'readwrite');
    const store = tx.objectStore(STORES.SESSION);
    
    await store.put({
        id: 'current',
        userId,
        token,
        privateKey,
        timestamp: Date.now()
    });
    
    // Also save to sessionStorage for quick access
    sessionStorage.setItem('userId', userId);
    sessionStorage.setItem('token', token);
    if (privateKey) {
        // In production, encrypt this!
        sessionStorage.setItem('hasKey', 'true');
    }
    
    return new Promise((resolve) => {
        tx.oncomplete = () => resolve(true);
    });
}

// Load session from IndexedDB
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
    
    // Also call logout endpoint
    await fetch('/api/logout', { method: 'POST' });
}

// Save private key
async function savePrivateKey(userId, keyId, privateKey) {
    const db = await initDB();
    const tx = db.transaction(STORES.KEYS, 'readwrite');
    const store = tx.objectStore(STORES.KEYS);
    
    await store.put({
        id: keyId,
        userId,
        privateKey,
        created: Date.now()
    });
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
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.error) {
            errorDiv.textContent = data.error;
        } else {
            // Save to IndexedDB
            await saveSession(data.user_id, data.token);
            
            // Show main app
            document.getElementById('auth-container').style.display = 'none';
            document.getElementById('app-container').style.display = 'block';
            document.getElementById('user-display').textContent = username;
            
            // Load user's groups
            loadUserGroups(data.user_id, data.token);
        }
    } catch (error) {
        errorDiv.textContent = 'Network error';
    }
}

// Handle Logout
async function handleLogout() {
    await clearSession();
    
    document.getElementById('auth-container').style.display = 'block';
    document.getElementById('app-container').style.display = 'none';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('login-error').textContent = '';
}

// Load user's groups (you'll implement this with your API)
async function loadUserGroups(userId, token) {
    // This will call your /users/me/groups endpoint
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const groups = await response.json();
        displayGroups(groups);
    } catch (error) {
        console.error('Failed to load groups:', error);
    }
}

// Display groups in the UI
function displayGroups(groups) {
    const groupsList = document.getElementById('groups-list');
    groupsList.innerHTML = '';
    
    groups.forEach(group => {
        const groupEl = document.createElement('div');
        groupEl.className = 'group-item';
        groupEl.innerHTML = `
            <div class="group-name">${group.group_name}</div>
            <div class="group-meta">${group.member_count} members</div>
        `;
        groupEl.onclick = () => selectGroup(group);
        groupsList.appendChild(groupEl);
    });
}

// Check for existing session on page load
window.addEventListener('load', async () => {
    const session = await loadSession();
    if (session) {
        // Auto-login with stored session
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').style.display = 'block';
        document.getElementById('user-display').textContent = session.userId;
        
        // Load user's groups
        loadUserGroups(session.userId, session.token);
    }
});

// Placeholder functions
function createGroup() {
    alert('Create group functionality coming soon!');
}

function selectGroup(group) {
    document.getElementById('group-name').textContent = group.group_name;
    document.getElementById('message-text').disabled = false;
    document.getElementById('send-btn').disabled = false;
}

function sendMessage() {
    const message = document.getElementById('message-text').value;
    if (message.trim()) {
        alert(`Send message: ${message}`);
        document.getElementById('message-text').value = '';
    }
}