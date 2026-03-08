# api_client.py
import requests
import json

BASE_URL = "http://localhost:8000"  # Your FastAPI backend

def register_user(username, password):
    """Call your /users endpoint"""
    try:
        response = requests.post(
            f"{BASE_URL}/users",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def login_user(username, password):
    """Call your /login endpoint"""
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}