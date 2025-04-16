import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (This should be kept secret in a real app)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# 1. In-Memory Data Storage
stored_data = {}  # Format: {"label": {"encrypted_text": "...", "passkey": "hashed"}}
failed_attempts = 0  # Tracks incorrect passkey attempts

# 2. Utility Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
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

# 4. Streamlit User Interface
st.title("🔐 Secure Data Storage & Retrieval")

# Navigation Menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure System")
    st.markdown("""
    - 🔐 **Encrypt and store** sensitive data with a unique passkey.
    - 🔍 **Retrieve and decrypt** your data securely.
    - 🔁 **Reauthorization** needed after 3 wrong attempts.
    - 🧠 All data is stored **in memory** (not in any file or database).
    """)

# Store Data Page
elif choice == "Store Data":
    st.subheader("📦 Store Data")
    label = st.text_input("Enter a label for your data (e.g. `user1_data`):")
    plain_text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and plain_text and passkey:
            encrypted = encrypt_data(plain_text)
            stored_data[label] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey)
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill all fields!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Data")
    label = st.text_input("Enter the label of your stored data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            if label in stored_data:
                encrypted = stored_data[label]["encrypted_text"]
                decrypted = decrypt_data(encrypted, passkey)
                if decrypted:
                    st.success("✅ Data Decrypted Successfully!")
                    st.code(decrypted, language="text")
                else:
                    st.error(f"❌ Incorrect passkey. Attempts left: {3 - failed_attempts}")
                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Please login again.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ No data found with this label.")
        else:
            st.error("⚠️ Both fields are required!")

# Login Page for Reauthorization
elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    master_pass = st.text_input("Enter admin password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # Hardcoded for demo
            failed_attempts = 0
            st.success("✅ Reauthorized. Please go back to 'Retrieve Data'.")
        else:
            st.error("❌ Wrong password.")
