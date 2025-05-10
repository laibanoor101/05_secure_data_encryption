import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def get_aes_key(passkey):
    """Generate 32-byte AES key using PBKDF2 from passkey"""
    return base64.urlsafe_b64decode(hash_passkey(passkey))

def encrypt_data(text, passkey="default"):
    key = get_aes_key(passkey)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_data(encrypted_text, passkey):
    if st.session_state.get("lockout_time"):
        elapsed = time.time() - st.session_state.lockout_time
        if elapsed < LOCKOUT_SECONDS:
            st.warning(f"🔒 Please wait {int(LOCKOUT_SECONDS - elapsed)} seconds before trying again.")
            return None

    try:
        encrypted_data = base64.b64decode(encrypted_text.encode())
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        key = get_aes_key(passkey)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        hashed_passkey = hash_passkey(passkey)
        for key_data, value in st.session_state.stored_data.items():
            if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return decrypted_data.decode()
    except Exception:
        pass

    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_time = time.time()
    return None
