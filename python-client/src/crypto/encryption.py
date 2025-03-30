from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class FileEncryption:
    def __init__(self, session_key):
        self.fernet = Fernet(self._derive_key(session_key))

    def _derive_key(self, session_key):
        """Derive a Fernet-compatible key from session key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'file_transfer_salt',  # Should be unique per session
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(session_key))
        return key

    def encrypt_file_data(self, file_data):
        """Encrypt file data using session-derived key"""
        return self.fernet.encrypt(file_data)

    def decrypt_file_data(self, encrypted_data):
        """Decrypt file data using session-derived key"""
        return self.fernet.decrypt(encrypted_data)