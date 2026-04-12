# 100_login.py
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

FLASK_URL = "http://localhost:5000"  # Flask (for key package generation)

def login_user(username, password):
    """Login a single user - key package generation happens inside Flask"""
    try:
        login_response = requests.post(
            f"{FLASK_URL}/api/login",
            json={"username": username, "password": password},
            timeout=30
        )
        
        if login_response.status_code != 200:
            print(f"❌ Login failed for {username}: {login_response.status_code}")
            return None
        
        data = login_response.json()
        if data.get('success'):
            return {
                "user_id": data.get('user_id'),
                "token": data.get('token'),
                "username": username
            }
        else:
            print(f"❌ Login failed for {username}: {data.get('error')}")
            return None
            
    except Exception as e:
        print(f"❌ Error logging in {username}: {str(e)}")
        return None

def login_100_users():
    users = []
    successful = 0
    failed = 0
    
    print("🚀 Starting login process for 100 users...")
    start_time = time.time()
    
    # Use ThreadPoolExecutor for concurrent logins (be careful with server load)
    with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced to 5 to avoid overwhelming
        futures = {}
        for i in range(1, 11):
            username = f"testuser{i}"
            password = "password123"
            future = executor.submit(login_user, username, password)
            futures[future] = username
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                users.append(result)
                successful += 1
                print(f"✅ [{successful}/100] Logged in: {result['username']}")
            else:
                failed += 1
                print(f"❌ Failed: {futures[future]}")
    
    elapsed = time.time() - start_time
    print(f"\n📊 Summary:")
    print(f"   ✅ Successful logins: {successful}")
    print(f"   ❌ Failed logins: {failed}")
    print(f"   ⏱️  Time taken: {elapsed:.2f} seconds")
    print(f"   📈 Rate: {successful/elapsed:.2f} users/second")
    
    return users

def check_active_sessions():
    """Debug: Check how many users are in active_sessions"""
    response = requests.get(f"{FLASK_URL}/api/debug/active-sessions")
    if response.status_code == 200:
        data = response.json()
        print(f"🔍 Active sessions on server: {data.get('count', 0)}")
        return data
    return None

if __name__ == "__main__": 
    print("="*50)
    print("MASS USER LOGIN TEST")
    print("="*50)
    
    # First, check server status
    try:
        resp = requests.get(f"{FLASK_URL}/api/debug/active-sessions")
        print(f"✅ Flask server is running at {FLASK_URL}")
    except:
        print(f"❌ Cannot reach Flask server at {FLASK_URL}")
        print("   Make sure your Flask app is running!")
        exit(1)
    
    # Login users
    users = login_100_users()
    
    # Verify active sessions
    time.sleep(1)
    check_active_sessions()
    
    # Save results
    import json
    with open("logged_in_users.json", "w") as f:
        json.dump(users, f, indent=2)
    print(f"\n💾 Saved {len(users)} user sessions to logged_in_users.json")