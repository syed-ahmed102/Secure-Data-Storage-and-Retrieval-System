import streamlit as st
from cryptography.fernet import Fernet
import base64

# --- In-Memory Storage ---
data_store = {}
failed_attempts = {}

# --- User Authentication ---
LOGIN_USERNAME = "admin"
LOGIN_PASSWORD = "password"

# --- Session State Initialization ---
if 'authorized' not in st.session_state:
    st.session_state.authorized = False
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'login_required' not in st.session_state:
    st.session_state.login_required = False


# --- Helper Functions ---
def generate_key(passkey):
    """Generate a Fernet key from the passkey."""
    key = base64.urlsafe_b64encode(passkey.ljust(32)[:32].encode())
    return key


def encrypt_data(data, passkey):
    key = generate_key(passkey)
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()


def decrypt_data(token, passkey):
    try:
        key = generate_key(passkey)
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except Exception:
        return None


def login_page():
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == LOGIN_USERNAME and password == LOGIN_PASSWORD:
            st.session_state.authorized = True
            st.session_state.attempts = 0
            st.session_state.login_required = False
            st.success("Login successful! Go to Home.")
        else:
            st.error("Invalid credentials")


# --- Pages ---
def home():
    st.title("🔐 Secure Data Vault")
    st.markdown("Welcome to your secure data storage.")
    st.page_link("main.py", label="Store New Data", section="store")
    st.page_link("main.py", label="Retrieve Data", section="retrieve")


def store_data():
    st.header("📥 Store Data")
    key = st.text_input("Enter a unique key (e.g., your name)")
    text = st.text_area("Enter data to encrypt")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Encrypt & Store"):
        if key and text and passkey:
            encrypted = encrypt_data(text, passkey)
            data_store[key] = encrypted
            failed_attempts[key] = 0
            st.success("Data securely stored!")
        else:
            st.warning("All fields are required!")


def retrieve_data():
    st.header("🔓 Retrieve Data")
    key = st.text_input("Enter the key for your data")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.session_state.attempts >= 3:
        st.session_state.login_required = True
        st.warning("Too many failed attempts. Please log in.")
        return

    if st.button("Decrypt"):
        if key in data_store:
            decrypted = decrypt_data(data_store[key], passkey)
            if decrypted:
                st.success("Decryption successful!")
                st.text_area("Your decrypted data", decrypted, height=200)
                st.session_state.attempts = 0
            else:
                st.session_state.attempts += 1
                st.error(f"Wrong passkey! Attempt #{st.session_state.attempts}")
        else:
            st.warning("No data found for this key")


# --- Navigation ---
st.sidebar.title("🔧 Menu")
page = st.sidebar.radio("Go to", ["Home", "Store Data", "Retrieve Data"])

# --- Login Lock ---
if st.session_state.login_required and not st.session_state.authorized:
    login_page()
else:
    if page == "Home":
        home()
    elif page == "Store Data":
        store_data()
    elif page == "Retrieve Data":
        retrieve_data()
