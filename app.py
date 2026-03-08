# app.py
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import os
from dotenv import load_dotenv
import api_client  # Your existing API client
from cryptography.fernet import Fernet
import base64

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)  # Enable CORS for development

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
    """Handle login - calls your existing API"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Call your existing API client
    result = api_client.login_user(username, password)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 401
    
    # Store in server session (optional - for additional security)
    session['user_id'] = result['user_id']
    session['token'] = result['access_token']
    
    return jsonify({
        'success': True,
        'user_id': result['user_id'],
        'token': result['access_token']
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear session"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/verify', methods=['GET'])
def verify():
    """Verify token is still valid"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'valid': False}), 401
    
    token = auth_header.split(' ')[1]
    # Here you could verify with your backend if needed
    
    return jsonify({'valid': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)