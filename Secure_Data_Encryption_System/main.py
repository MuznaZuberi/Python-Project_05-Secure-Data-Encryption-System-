# =============================== Secure Data Encryption System | By Muzna Amir Zubairi ===============================

import streamlit as st
import hashlib
import json
import os
import time

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def simple_encrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def simple_decrypt(cipher_text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(cipher_text))

stored_data = load_data()

st.title("🔐 Secure Data Encryption Hub")
menu = ["HOME", "REGISTER", "LOGIN", "STORE DATA", "RETRIEVE DATA"]
choice = st.sidebar.selectbox("📁 Navigation Menu", menu)

if choice == "HOME":
    st.subheader("👋 Welcome to Your Personal Encryption Vault")
    st.markdown("Securely store and retrieve your confidential information. This system uses a basic encryption mechanism for educational purposes. Multiple login failures result in a temporary lockout. No third-party databases involved.")

elif choice == "REGISTER":
    st.subheader("📝 Register for Secure Access")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("User already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully!")
        else:
            st.error("Both fields are required")

elif choice == "LOGIN":
    st.subheader("🔑 Login to Your Vault")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("Too many failed attempts. Locked for 60 seconds.")
                st.stop()

elif choice == "STORE DATA":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        st.subheader("📦 Encrypt and Store Your Sensitive Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = simple_encrypt(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and saved successfully!")
            else:
                st.error("All fields are required")

elif choice == "RETRIEVE DATA":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        st.subheader("🔓 Decrypt and View Stored Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found!")
        else:
            st.write("🔐 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = simple_decrypt(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted: {result}")
                else:
                    st.error("Incorrect passkey or corrupted data")
