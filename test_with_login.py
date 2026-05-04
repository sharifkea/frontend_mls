# test_with_login.py
import requests
import time
import statistics

def test_with_login(username, password, group_id_hex):
    """Test by logging in first to get session cookie"""
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    # 1. Login to FLASK (not FastAPI)
    print("Logging in...")
    login_response = session.post(
        "http://localhost:5000/api/login",  # ← Fixed: Flask endpoint
        json={"username": username, "password": password}
    )
    
    print(f"Login response status: {login_response.status_code}")
    
    if login_response.status_code != 200:
        print(f"Login failed: {login_response.text}")
        return
    
    data = login_response.json()
    print(f"Logged in as: {data['username']}")
    print(f"User ID: {data['user_id']}")
    print(f"Token: {data['token'][:50]}...")
    
    # 2. Test send message
    print("\n📤 Testing send message...")
    times = []
    
    for i in range(5):  # Reduce iterations for quick test
        start = time.perf_counter()
        response = session.post(
            "http://localhost:5000/api/messages/send",
            json={
                "group_id_hex": group_id_hex,
                "message": f"Test message {i}"
            }
        )
        end = time.perf_counter()
        
        if response.status_code == 200:
            times.append((end - start) * 1000)
            print(f"   Message {i+1}: {times[-1]:.2f} ms")
        else:
            print(f"   Error {i+1}: {response.status_code} - {response.text[:100]}")
    
    if times:
        print(f"\n   ✅ Send message avg: {statistics.mean(times):.2f} ms")
        print(f"   Min: {min(times):.2f} ms, Max: {max(times):.2f} ms")
    
    # 3. Test get messages
    print("\n📥 Testing get messages...")
    times = []
    
    for i in range(5):
        start = time.perf_counter()
        response = session.post(
            "http://localhost:5000/api/messages/get",
            json={"group_id_hex": group_id_hex}
        )
        end = time.perf_counter()
        
        if response.status_code == 200:
            times.append((end - start) * 1000)
            print(f"   Get {i+1}: {times[-1]:.2f} ms")
        else:
            print(f"   Error {i+1}: {response.status_code}")
    
    if times:
        print(f"\n   ✅ Get messages avg: {statistics.mean(times):.2f} ms")
        print(f"   Min: {min(times):.2f} ms, Max: {max(times):.2f} ms")
    
    return {
        'send_latency': statistics.mean(times) if times else None,
        'get_latency': statistics.mean(times) if times else None,
        'total_messages': len(times)
    }


if __name__ == "__main__":
    # Replace with your actual credentials
    # You need to use a valid username and password that exists in your system
    USERNAME = "alice"  # Change to your username
    PASSWORD = "your_password_here"  # Change to your password
    GROUP_ID_HEX = "ae214897af81bf7ec1c58900dae0c828"  # Your group hex
    
    print("=" * 60)
    print("MLS Performance Test (Browser Session Style)")
    print("=" * 60)
    
    result = test_with_login(USERNAME, PASSWORD, GROUP_ID_HEX)
    
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    if result and result.get('send_latency'):
        print(f"  Send Message:    {result['send_latency']:.2f} ms")
        print(f"  Get Messages:    {result['get_latency']:.2f} ms")