import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from app import app

client = app.test_client()

print("--- 1. SUCCESSFUL LOGIN ATTEMPT ---")
res1 = client.post('/login', data={'username': 'admin', 'password': '1234'})
print('"POST /login HTTP/1.1"', res1.status_code)
print('Browser output:', res1.data.decode())

print("\n--- 2. FAILED LOGIN ATTEMPT ---")
res2 = client.post('/login', data={'username': 'user1', 'password': 'wrongpassword'})
print('"POST /login HTTP/1.1"', res2.status_code)
print('Browser output:', res2.data.decode())
