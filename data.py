import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (in production, load securely from file/env)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory database
stored_data = {}
failed_attempts = 0

# -----------------------
# Utility Functions
# -----------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# -----------------------
# Streamlit UI Layout
# -----------------------

st.set_page_config(page_title="🔐 Secure Storage", layout="centered")

# Sidebar Menu (Menu Bar)
st.sidebar.title("🔐 Secure Menu")
menu = st.sidebar.radio("Navigate", ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🔑 Login"])

st.markdown("<hr>", unsafe_allow_html=True)

# -----------------------
# Page Logic
# -----------------------

if menu == "🏠 Home":
    st.title("🏠 Welcome to Secure Data Storage")
    st.markdown("""
        Use this tool to **store** and **retrieve** sensitive data securely using a passkey.  
        Features include:
        - 🔐 AES encryption using Fernet
        - 🧠 In-memory storage (no database)
        - 🚫 Lockout after 3 failed decryption attempts  
        - 🔑 Simple reauthentication to continue  
    """)

elif menu == "📂 Store Data":
    st.title("📂 Store Your Data")
    user_data = st.text_area("🔸 Enter the data you want to secure:")
    passkey = st.text_input("🔑 Set a secure passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data, passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Your data has been encrypted and stored securely!")
            st.code(encrypted, language='text')
        else:
            st.error("⚠️ Please enter both data and a passkey.")

elif menu == "🔍 Retrieve Data":
    st.title("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("🔸 Paste your encrypted data here:")
    passkey = st.text_input("🔑 Enter your passkey:", type="password")

    if st.button("Decrypt Data"):
        if encrypted_input and passkey:
            decrypted = decrypt_data(encrypted_input, passkey)
            if decrypted:
                st.success("✅ Decryption successful!")
                st.code(decrypted, language='text')
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 3 failed attempts! Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif menu == "🔑 Login":
    st.title("🔑 Reauthorization")
    login = st.text_input("🔐 Enter master password to reset:", type="password")

    if st.button("Login"):
        if login == "admin123":  # Demo password
            failed_attempts = 0
            st.success("✅ Reauthorized! You can now try retrieving data again.")
        else:
            st.error("❌ Wrong password. Try again.")
