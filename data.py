import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import base64

# --- Global In-Memory Storage ---
data_store = {}
failed_attempts = 0

# --- Fernet Key Generation (Based on User Passkey) ---
def generate_key(passkey):
    # Pad or trim passkey to 32 bytes, then base64 encode it
    passkey = passkey.ljust(32)[:32]  # Ensure 32 bytes
    return base64.urlsafe_b64encode(passkey.encode())

# --- Encrypt and Decrypt Functions ---
def encrypt_data(text, passkey):
    key = generate_key(passkey)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_data(token, passkey):
    key = generate_key(passkey)
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

# --- Page Navigation ---
def show_home():
    st.title("🔐 Secure Data Storage")
    st.write("Choose an option below:")
    if st.button("Store New Data"):
        st.session_state.page = "store"
    if st.button("Retrieve Data"):
        st.session_state.page = "retrieve"

def show_store():
    st.title("📥 Store Data")
    data_key = st.text_input("Enter a Key to Store Data (like 'email')")
    data_value = st.text_area("Enter the Data")
    passkey = st.text_input("Enter a Passkey for Encryption", type="password")
    if st.button("Encrypt & Store"):
        if data_key and data_value and passkey:
            encrypted = encrypt_data(data_value, passkey)
            data_store[data_key] = encrypted
            st.success("Data encrypted and stored successfully.")
        else:
            st.error("Please fill all fields.")
    st.button("Back to Home", on_click=lambda: st.session_state.update(page="home"))

def show_retrieve():
    global failed_attempts
    st.title("📤 Retrieve Data")
    data_key = st.text_input("Enter the Key to Retrieve Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Retrieve"):
        if data_key in data_store:
            try:
                decrypted = decrypt_data(data_store[data_key], passkey)
                st.success("Decrypted Data:")
                st.code(decrypted)
                failed_attempts = 0  # Reset on success
            except InvalidToken:
                failed_attempts += 1
                st.error(f"Decryption failed! Attempts: {failed_attempts}/3")
                if failed_attempts >= 3:
                    st.session_state.page = "login"
        else:
            st.error("Key not found.")

    st.button("Back to Home", on_click=lambda: st.session_state.update(page="home"))

def show_login():
    global failed_attempts
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            failed_attempts = 0
            st.session_state.page = "home"
            st.success("Login successful. Redirecting to Home.")
        else:
            st.error("Invalid credentials.")

def main():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    if st.session_state.page == "home":
        show_home()
    elif st.session_state.page == "store":
        show_store()
    elif st.session_state.page == "retrieve":
        show_retrieve()
    elif st.session_state.page == "login":
        show_login()

if __name__ == "__main__":
    main()
