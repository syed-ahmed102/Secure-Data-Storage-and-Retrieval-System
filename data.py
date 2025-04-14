import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- App Config ---
st.set_page_config(page_title="Secure Data App", page_icon="🔐")

# --- Encryption Key ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- In-Memory Storage ---
stored_data = {}  # {encrypted_text: {"encrypted_text": ..., "passkey": hashed_passkey}}
failed_attempts = 0


# --- Utility Functions ---

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


def verify_and_decrypt(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    if encrypted_text in stored_data:
        stored_passkey = stored_data[encrypted_text]["passkey"]
        if hashed_passkey == stored_passkey:
            failed_attempts = 0
            return decrypt_data(encrypted_text)

    failed_attempts += 1
    return None


# --- Sidebar Navigation ---
st.sidebar.title("🔐 Navigation")
menu = st.sidebar.radio("Go to", ["Home", "Store Data", "Retrieve Data", "Login"])

# --- Pages ---

if menu == "Home":
    st.title("🏠 Welcome to Secure Data System")
    st.markdown("This app lets you **encrypt** and **retrieve** data using a passkey.")
    st.markdown("- 🔒 All data is stored in memory.")
    st.markdown("- 🧠 Passkeys are hashed with SHA-256.")
    st.markdown("- 🧪 Encryption uses **Fernet** from the `cryptography` module.")

elif menu == "Store Data":
    st.header("📂 Store Data Securely")

    text = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(text)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored securely!")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Please enter both text and a passkey.")

elif menu == "Retrieve Data":
    st.header("🔍 Retrieve Stored Data")

    encrypted_input = st.text_area("Paste encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = verify_and_decrypt(encrypted_input, passkey_input)

            if result:
                st.success("✅ Decrypted Data:")
                st.code(result, language='text')
            else:
                attempts_left = max(0, 3 - failed_attempts)
                st.error(f"❌ Incorrect passkey. Attempts remaining: {attempts_left}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Please enter both encrypted data and passkey.")

elif menu == "Login":
    st.header("🔑 Reauthorization")

    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with a secure method in production
            failed_attempts = 0
            st.success("✅ Reauthorized! You may now decrypt again.")
            st.experimental_rerun()
        else:
            st.error("❌ Invalid password!")
