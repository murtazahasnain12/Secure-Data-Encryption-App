import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os

# --- Session State Initialization ---
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = False

# --- Key Handling (Persistent) ---
KEY_FILE = "fernet_key.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    KEY = f.read()

cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Format: {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}

# --- Helper Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    data = stored_data.get(encrypted_text)

    if data and data["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- Streamlit UI ---
st.title("\U0001F512 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("\U0001F3E0 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("\U0001F4C2 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("\u2705 Data stored securely!")
            st.code(encrypted_text, language='text')
        else:
            st.error("\u26A0\uFE0F Both fields are required!")

elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.authorized:
        st.warning("\U0001F512 Too many failed attempts. Please reauthorize on the Login Page.")
    else:
        st.subheader("\U0001F50D Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success(f"\u2705 Decrypted Data: {decrypted_text}")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"\u274C Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("\U0001F512 Too many failed attempts! Redirecting to Login Page...")
                        st.experimental_rerun()
            else:
                st.error("\u26A0\uFE0F Both fields are required!")

elif choice == "Login":
    st.subheader("\U0001F511 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("\u2705 Reauthorized successfully! You can now retry data decryption.")
        else:
            st.error("\u274C Incorrect master password!")

