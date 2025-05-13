import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

DB_FILE = "simple_data.db"
KEY_FILE = "simple_secret.key"

# --- Encryption key load karo ya nayi banao agar nahi hai ---
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())

# --- Database sirf aik dafa initialize hoga ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            label TEXT PRIMARY KEY,
            encrypted_text TEXT,
            passkey TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Passkey ko hash karo secure banane ke liye ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Text ko encrypt karo ---
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

# --- Encrypted text ko decrypt karo ---
def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Streamlit UI start ---
st.title("🔐 Secure Data Encryption App")

menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("Kya karna chahte ho?", menu)

# --- Agar user secret store karna chahta hai ---
if choice == "Store Secret":
    st.header("🔒 Store a New Secret")

    label = st.text_input("Enter a label (e.g., email, password, etc.)")
    secret = st.text_area("Enter the secret you want to save")
    passkey = st.text_input("Enter a passkey (required)", type="password")

    if st.button("Encrypt and Save"):
        if label and secret and passkey:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            encrypted = encrypt(secret)
            hashed_key = hash_passkey(passkey)

            try:
                c.execute("INSERT INTO vault (label, encrypted_text, passkey) VALUES (?, ?, ?)",
                          (label, encrypted, hashed_key))
                conn.commit()
                st.success("✅ Secret saved successfully!")
            except sqlite3.IntegrityError:
                st.error("⚠️ This label already exists. Try a different one.")
            finally:
                conn.close()
        else:
            st.warning("⚠️ All fields are required!")

# --- Agar user secret retrieve karna chahta hai ---
elif choice == "Retrieve Secret":
    st.header("🔓 Retrieve Your Secret")

    label = st.text_input("Enter the label you used")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT encrypted_text, passkey FROM vault WHERE label=?", (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_text, stored_hashed = result
                if hash_passkey(passkey) == stored_hashed:
                    try:
                        decrypted = decrypt(encrypted_text)
                        st.success("✅ Your secret is:")
                        st.code(decrypted)
                    except:
                        st.error("❌ Decryption failed.")
                else:
                    st.error("❌ Incorrect passkey.")
            else:
                st.warning("⚠️ No such label found in the database.")
        else:
            st.warning("⚠️ Both label and passkey are required.")
