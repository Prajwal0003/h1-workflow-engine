import sqlite3
import time
import os
import sys

db_path = r"c:\Users\prajw\.openclaw\workspace\h1-workflow\data\freellmapi\freeapi.db"
env_path = r"c:\Users\prajw\.openclaw\workspace\h1-workflow\.env"

print("[*] Waiting for FreeLLMAPI proxy to generate SQLite database...")
while not os.path.exists(db_path):
    time.sleep(2)

print("[+] Database found! Waiting for tables to initialize...")
time.sleep(5)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

key = None
for _ in range(15):
    try:
        cursor.execute("SELECT value FROM settings WHERE key='unified_api_key'")
        row = cursor.fetchone()
        if row:
            key = row[0]
            break
    except Exception as e:
        pass
    time.sleep(2)

if key:
    print(f"[+] Master key intercepted: {key}")
    with open(env_path, "r") as f:
        env_content = f.read()
    
    if "FREELLMAPI_KEY" in env_content:
        print("[i] FREELLMAPI_KEY already exists in .env")
    else:
        with open(env_path, "a") as f:
            f.write(f'\nFREELLMAPI_URL="http://localhost:3001/v1"\n')
            f.write(f'FREELLMAPI_KEY="{key}"\n')
        print("[+] Automatically injected master key into .env pipeline!")
else:
    print("[-] Could not intercept key from DB.")
