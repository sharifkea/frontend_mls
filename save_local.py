import csv
import os

def get_privetKey(user_id, group_id):
    filename = f"files/{user_id}.csv"
    if not os.path.exists(filename):
        return None  

    creds = {}
    with open(filename, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            creds[row['groupId']] = row['privateKey']

    return creds.get(group_id)

def save_privetKey(user_id, group_id, private_key):
    filename = f"files/{user_id}.csv"
    headers = ['groupId', 'privateKey']
    
    # 1. Load existing data first (to avoid overwriting other groups)
    creds = {}
    if os.path.exists(filename):
        with open(filename, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                creds[row['groupId']] = row['privateKey']

    # 2. Update with the new key
    creds[group_id] = private_key

    # 3. Save everything back to the file
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for g_id, p_key in creds.items():
            writer.writerow({'groupId': g_id, 'privateKey': p_key})
    
    return True
