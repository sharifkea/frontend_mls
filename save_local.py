import csv
import os
import base64
import platform

def get_storage_path():
    """Get platform-specific storage directory"""
    system = platform.system()
    app_name = "MLSMessenger"
    
    if system == "Windows":
        base = os.getenv('APPDATA')
    elif system == "Darwin":  # macOS
        base = os.path.expanduser('~/Library/Application Support')
    else:  # Linux
        base = os.path.expanduser('~/.config')
    
    path = os.path.join(base, app_name)
    os.makedirs(path, exist_ok=True)
    return path

def get_final_secret(user_id, group_id):
    storage_path = get_storage_path()
    print(f"Looking for credentials in: {storage_path}")
    filename = os.path.join(storage_path, f"{user_id}.csv")
    if not os.path.exists(filename):
        return None

    creds = {}
    with open(filename, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            creds[row['groupId']] = row['finalSecret']

    result = creds.get(group_id)
    if result:
        # Return as bytes if it looks like hex
        try:
            return bytes.fromhex(result)
        except:
            return result.encode() if isinstance(result, str) else result
    return None

def save_final_secret(user_id, group_id, final_secret):
    storage_path = get_storage_path()
    filename = os.path.join(storage_path, f"{user_id}.csv")
    headers = ['groupId', 'finalSecret']
    
    # Convert bytes to hex string for CSV storage
    if isinstance(final_secret, bytes):
        final_secret = final_secret.hex()
    
    # Load existing data
    creds = {}
    if os.path.exists(filename):
        with open(filename, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                creds[row['groupId']] = row['finalSecret']

    # Update with new key
    creds[group_id] = final_secret

    # Save everything back
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for g_id, s_sec in creds.items():
            writer.writerow({'groupId': g_id, 'finalSecret': s_sec})
    
    return True
