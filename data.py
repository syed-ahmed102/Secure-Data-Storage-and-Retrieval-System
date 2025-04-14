import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import base64

# --- Simulated database (in-memory) ---
data_store = {}
failed_attempts = {}

# --- Session State Initialization ---
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "max_attempts" not in st.session_state:
    st.session_state.max_attempts = 3

# --- Functions ---
def generate_key(passkey: str) -> bytes:
    # Normalize passkey to 32 bytes for Fernet
    key = base64.urlsafe_b64encode(passkey.ljust(32)[:32].encode())
    return key

def encrypt_data(text: str, passkey: str) -> bytes:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(text.encode())

def decrypt_data(encrypted_data: bytes, passkey: str) -> str:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

def login_page():
    st.title("🔐 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.session_state.authenticated = True
            st.session_state.login_attempts = 0
            st.success("Logged in successfully!")
        else:
            st.error("Incorrect login credentials")

def home_page():
    st.title("🏠 Secure Data Storage")
    st.write("Choose an option below:")
    if st.button("Insert New Data"):
        st.session_state.page = "insert"
    if st.button("Retrieve Data"):
        st.session_state.page = "retrieve"

def insert_data_page():
    st.title("📝 Insert Data")
    key = st.text_input("Key for data")
    text = st.text_area("Enter text")
    passkey = st.text_input("Enter passkey", type="password")
    if st.button("Store Securely"):
        encrypted = encrypt_data(text, passkey)
        data_store[key] = encrypted
        st.success("Data stored securely!")

def retrieve_data_page():
    st.title("🔍 Retrieve Data")
    key = st.text_input("Enter the key")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve"):
        if st.session_state.login_attempts >= st.session_state.max_attempts:
            st.error("Maximum attempts reached. Redirecting to login page...")
            st.session_state.authenticated = False
            return

        encrypted_data = data_store.get(key)
        if not encrypted_data:
            st.warning("No data found for this key.")
            return

        try:
            decrypted = decrypt_data(encrypted_data, passkey)
            st.success("Decrypted Data:")
            st.code(decrypted)
            st.session_state.login_attempts = 0  # reset after successful attempt
        except (InvalidToken, Exception):
            st.session_state.login_attempts += 1
            remaining = st.session_state.max_attempts - st.session_state.login_attempts
            st.error(f"Invalid passkey. Attempts left: {remaining}")

def main():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    if not st.session_state.authenticated:
        login_page()
        return

    if st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "insert":
        insert_data_page()
    elif st.session_state.page == "retrieve":
        retrieve_data_page()

    st.sidebar.title("Navigation")
    if st.sidebar.button("🏠 Home"):
        st.session_state.page = "home"
    if st.sidebar.button("🔓 Logout"):
        st.session_state.authenticated = False
        st.session_state.login_attempts = 0

if __name__ == "__main__":
    main()