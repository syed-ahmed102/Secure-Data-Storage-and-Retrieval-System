import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (store securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # {"user_label": {"encrypted_text": "...", "passkey": "hashed"}}
failed_attempts = 0

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    label = st.text_input("Enter a Label for Your Data (e.g. user1_data):")
    user_data = st.text_area("Enter the Data You Want to Store:")
    passkey = st.text_input("Enter a Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[label] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    label = st.text_input("Enter the Label Used to Store Data:")
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            if label in stored_data:
                encrypted_text = stored_data[label]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passkey)

                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ No data found with this label.")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Simple hardcoded master password
            failed_attempts = 0
            st.success("✅ Access Restored! You can now try again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")
