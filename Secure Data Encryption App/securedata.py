import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time
import json
import os

# Generate or load encryption key
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return open("secret.key", "rb").read()

KEY = load_key()
cipher = Fernet(KEY)

# User data storage
USER_DATA_FILE = "users.json"
ENCRYPTED_DATA_FILE = "encrypted_data.json"

# Load user data
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save user data
def save_users(users):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)

# Load encrypted data
def load_encrypted_data():
    if os.path.exists(ENCRYPTED_DATA_FILE):
        with open(ENCRYPTED_DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save encrypted data
def save_encrypted_data(data):
    with open(ENCRYPTED_DATA_FILE, "w") as f:
        json.dump(data, f)

# Initialize data
users = load_users()
encrypted_data = load_encrypted_data()
failed_attempts = {}
lockout_time = {}

# Password hashing with salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return hashed, salt

# Encryption functions
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Authentication functions
def is_authenticated():
    return st.session_state.get('authenticated', False)

def is_locked_out(username):
    if username in lockout_time and lockout_time[username] > time.time():
        return True
    return False

# Custom CSS for styling
st.markdown("""
    <style>
        body {
            background-color: #e0f7fa;
            font-family: 'Arial', sans-serif;
        }
        .stButton button {
            background-color: #5C6BC0;
            color: white;
            font-size: 16px;
            font-weight: bold;
            border-radius: 8px;
        }
        .stButton button:hover {
            background-color: #3949AB;
        }
        .stTextInput input {
            background-color: #ffffff;
            border: 2px solid #ccc;
            padding: 10px;
            border-radius: 6px;
        }
        .stTextArea textarea {
            background-color: #ffffff;
            border: 2px solid #ccc;
            padding: 10px;
            border-radius: 6px;
        }
        .stTextInput, .stTextArea {
            margin-bottom: 16px;
        }
        .stForm {
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin-top: 20px;
        }
        .stTitle {
            color: #5C6BC0;
        }
        .stError {
            color: #e74c3c;
        }
        .stSuccess {
            color: #27ae60;
        }
    </style>
""", unsafe_allow_html=True)

# Registration page
def register_page():
    st.title("🔐 User Registration")
    
    with st.form("register_form"):
        username = st.text_input("Choose a username", help="Your unique username for login")
        password = st.text_input("Choose a password", type="password", help="Password must be at least 6 characters")
        confirm_password = st.text_input("Confirm password", type="password")
        
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if not username or not password:
                st.error("Username and password are required!")
            elif password != confirm_password:
                st.error("Passwords don't match!")
            elif username in users:
                st.error("Username already exists!")
            else:
                hashed_password, salt = hash_password(password)
                users[username] = {
                    'hashed_password': hashed_password,
                    'salt': salt
                }
                save_users(users)
                encrypted_data[username] = {}
                save_encrypted_data(encrypted_data)
                st.success("Registration successful! Please login.")

# Login page
def login_page():
    st.title("🔒 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username", help="Enter your username")
        password = st.text_input("Password", type="password", help="Enter your password")
        
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if is_locked_out(username):
                remaining_time = int(lockout_time[username] - time.time())
                st.error(f"Account locked. Please try again in {remaining_time} seconds.")
                return
            
            if username not in users:
                st.error("Invalid username or password")
                return
            stored_data = users[username]
            hashed_input, _ = hash_password(password, stored_data['salt'])
            
            if hashed_input == stored_data['hashed_password']:
                st.session_state['authenticated'] = True
                st.session_state['username'] = username
                failed_attempts[username] = 0
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()
            else:
                failed_attempts[username] = failed_attempts.get(username, 0) + 1
                st.error(f"Invalid credentials. Attempt {failed_attempts[username]} of 3.")
                
                if failed_attempts[username] >= 3:
                    lockout_time[username] = time.time() + 30  # 30 second lockout
                    st.error("Too many failed attempts. Account locked for 30 seconds.")

# Main app
def main_app():
    st.title("🔒 Secure Data Encryption System")
    
    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)
    
    if choice == "Home":
        st.subheader("🏠 Home")
        st.write(f"Welcome, {st.session_state['username']}!")
        st.write("Use this app to securely store and retrieve your data.")
        st.write("""
            **How to Use:**
            1. **Register**: First, create a username and password to register.
            2. **Login**: Use your username and password to log in.
            3. **Store Data**: Encrypt your sensitive data using a passkey and store it securely.
            4. **Retrieve Data**: Retrieve your stored data by decrypting it with your passkey.
        """)
        
    elif choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        
        with st.form("store_form"):
            data_name = st.text_input("Data identifier (e.g., 'personal notes')")
            user_data = st.text_area("Data to encrypt")
            passkey = st.text_input("Encryption passkey", type="password")
            
            submitted = st.form_submit_button("Encrypt & Save")
            
            if submitted:
                if not data_name or not user_data or not passkey:
                    st.error("All fields are required!")
                else:
                    username = st.session_state['username']
                    hashed_passkey, salt = hash_password(passkey)
                    
                    if username not in encrypted_data:
                        encrypted_data[username] = {}
                    
                    encrypted_data[username][data_name] = {
                        'encrypted_text': encrypt_data(user_data),
                        'passkey_hash': hashed_passkey,
                        'salt': salt
                    }
                    save_encrypted_data(encrypted_data)
                    st.success("Data stored securely!")
    
    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        username = st.session_state['username']
        
        if username not in encrypted_data or not encrypted_data[username]:
            st.error("No stored data found for your account.")
            return
            
        data_name = st.selectbox("Select data to retrieve", list(encrypted_data[username].keys()))
        
        with st.form("retrieve_form"):
            passkey = st.text_input("Enter passkey", type="password")
            
            submitted = st.form_submit_button("Decrypt Data")
            
            if submitted:
                if not passkey:
                    st.error("Passkey is required!")
                else:
                    data = encrypted_data[username][data_name]
                    hashed_input, _ = hash_password(passkey, data['salt'])
                    
                    if hashed_input == data['passkey_hash']:
                        decrypted_text = decrypt_data(data['encrypted_text'])
                        st.success("Decrypted successfully!")
                        st.text_area("Decrypted Data", value=decrypted_text, height=200)
                    else:
                        st.error("Incorrect passkey!")
    
    elif choice == "Logout":
        st.session_state['authenticated'] = False
        st.session_state.pop('username', None)
        st.success("Logged out successfully!")
        time.sleep(1)
        st.rerun()

# Main app flow
def main():
    if not is_authenticated():
        tab1, tab2 = st.tabs(["Login", "Register"])
        with tab1:
            login_page()
        with tab2:
            register_page()
    else:
        main_app()

if __name__ == "__main__":
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    main()