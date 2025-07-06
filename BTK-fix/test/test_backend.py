import requests
import json

BASE_URL = "http://127.0.0.1:5000"

session = requests.Session()
test_username = "alice_test"
test_password = "alice123"
test_fullname = "Alice Tester"

print("\U0001F9EA RUNNING BACKEND TEST SUITE")
print("=" * 50)

# 1. Register user
print("\U0001F539 Registering new user...")
res = session.post(
    f"{BASE_URL}/register",
    data={"username": test_username, "password": test_password, "fullname": test_fullname},
    allow_redirects=False
)
if res.status_code in [302, 200]:
    print("✅ Register success (or already exists)")
else:
    print(f"❌ Register failed: {res.status_code}, {res.text}")

# 2. Login
print("\U0001F539 Logging in...")
res = session.post(
    f"{BASE_URL}/login",
    data={"username": test_username, "password": test_password},
    allow_redirects=False
)
if res.status_code in [302, 200]:
    print("✅ Login success")
else:
    print(f"❌ Login failed: {res.status_code}, {res.text}")

# 3. /sign_info
print("\U0001F539 Testing /sign_info...")
sample_info = {"user": test_username, "role": "tester"}
res = session.post(f"{BASE_URL}/sign_info", json=sample_info)
try:
    result = res.json()
    if "signature" in result:
        print("✅ Sign info success")
    else:
        print(f"❌ Sign info failed: {result}")
except Exception:
    print(f"❌ Sign info failed: status={res.status_code}, response={res.text}")

# 4. /get_public_key
print("\U0001F539 Testing /get_public_key...")
res = session.get(f"{BASE_URL}/get_public_key", params={"username": test_username})
try:
    result = res.json()
    public_key_pem = result.get("public_key")
    if public_key_pem:
        print("✅ Get public key success")
    else:
        print(f"❌ Get public key failed: {result}")
except Exception:
    print(f"❌ Get public key failed: status={res.status_code}, response={res.text}")

# 5. /debug_keys
print("\U0001F539 Testing /debug_keys...")
res = session.get(f"{BASE_URL}/debug_keys")
try:
    result = res.json()
    if "private_key_size" in result:
        print("✅ Debug keys success")
    else:
        print(f"❌ Debug keys failed: {result}")
except Exception:
    print(f"❌ Debug keys failed: status={res.status_code}, response={res.text}")

# 6. /decrypt_des_key
print("\U0001F539 Testing /decrypt_des_key...")
import base64, os
fake_des_key = os.urandom(8)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# Get public key again
res = session.get(f"{BASE_URL}/get_public_key", params={"username": test_username})
try:
    result = res.json()
    key_data = result.get("public_key")
    if not key_data:
        raise ValueError("Missing public key")
    pub_key = RSA.import_key(key_data.encode())
    cipher_rsa = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    enc_key = cipher_rsa.encrypt(fake_des_key)
    enc_b64 = base64.b64encode(enc_key).decode()
    res = session.post(f"{BASE_URL}/decrypt_des_key", json={"encrypted_des_key": enc_b64})
    result = res.json()
    if "des_data" in result:
        print("✅ Decrypt DES key success")
    else:
        print(f"❌ Decrypt DES key failed: {result}")
except Exception as e:
    print(f"❌ Decrypt DES key test failed: {e}")
