import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key (temporary for in-memory use)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory dictionary
stored_data = {}  # {"user1_data": {"encrypted_text": "ciphertext", "passkey": "hashed_pass"}}
failed_attempts = 0

# Hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt plain text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt encrypted text
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed = hash_passkey(passkey)
    for data in stored_data.values():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    failed_attempts += 1
    return None

# Streamlit App Interface
st.title("🔐 Secure Data Storage & Retrieval")

# Navigation Menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.header("🏠 Welcome!")
    st.write("Use this app to securely store and retrieve data using encryption and passkeys.")

elif choice == "Store Data":
    st.header("📦 Store Data")
    label = st.text_input("Label (e.g. user1_data):")
    plain_text = st.text_area("Enter your secret text:")
    passkey = st.text_input("Create Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if label and plain_text and passkey:
            encrypted = encrypt_data(plain_text)
            hashed = hash_passkey(passkey)
            stored_data[label] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.header("🔍 Retrieve Data")
    label = st.text_input("Data Label:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if label in stored_data and passkey:
            encrypted = stored_data[label]["encrypted_text"]
            decrypted = decrypt_data(encrypted, passkey)
            if decrypted:
                st.success("✅ Data Decrypted:")
                st.write(decrypted)
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Invalid label or missing input.")

elif choice == "Login":
    st.header("🔐 Login Required")
    login_pass = st.text_input("Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Demo only
            failed_attempts = 0
            st.success("✅ Reauthorized. Returning to Retrieve Data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
