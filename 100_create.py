# test_mass_users.py
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://localhost:8000"  # FastAPI backend

def create_user(username, password):
    """Register a single user"""
    # 1. Register user
    reg_response = requests.post(
        f"{BASE_URL}/users",
        json={"username": username, "password": password}
    )
    if reg_response.status_code != 200:
        return None
    
    user_id = reg_response.json().get("user_id")
    
    return {"user_id": user_id, "username": username}

# Run for 100 users
def create_100_users():
    users = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i in range(1, 11):
            username = f"testuser{i}"
            password = "password123"
            futures.append(executor.submit(create_user, username, password))
        
        for future in futures:
            result = future.result()
            if result:
                users.append(result)
                print(f"✅ Created: {result['username']}")
    
    print(f"\n✅ Created {len(users)} users")
    return users

if __name__ == "__main__": 
    create_100_users()