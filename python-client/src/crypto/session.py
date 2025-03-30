from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import os
import time
import logging

logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.sessions = {}
        self.session_lifetime = 3600  # 1 hour session lifetime

    def create_session(self, peer_id):
        """Create new DH keypair for session"""
        private_key = self.parameters.generate_private_key()
        public_key = private_key.public_key()
        
        self.sessions[peer_id] = {
            'private_key': private_key,
            'public_key': public_key,
            'created_at': time.time(),
            'shared_key': None,
            'fernet': None
        }
        return public_key

    def complete_session(self, peer_id, peer_public_key):
        """Complete session setup with peer's public key"""
        if peer_id not in self.sessions:
            raise ValueError("No session initiated for peer")
            
        session = self.sessions[peer_id]
        shared_key = session['private_key'].exchange(peer_public_key)
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        
        # Create Fernet instance for symmetric encryption
        session['shared_key'] = shared_key
        session['fernet'] = Fernet(Fernet.generate_key())
        
        logger.info(f"Established session with peer: {peer_id}")
        return True

    def encrypt_message(self, peer_id, message):
        """Encrypt message using session key"""
        if not self._is_session_valid(peer_id):
            raise ValueError("No valid session")
        return self.sessions[peer_id]['fernet'].encrypt(message)

    def decrypt_message(self, peer_id, encrypted_message):
        """Decrypt message using session key"""
        if not self._is_session_valid(peer_id):
            raise ValueError("No valid session")
        return self.sessions[peer_id]['fernet'].decrypt(encrypted_message)

    def rotate_session(self, peer_id):
        """Rotate session keys"""
        if peer_id in self.sessions:
            logger.info(f"Rotating session for peer: {peer_id}")
            old_session = self.sessions[peer_id]
            
            # Create new DH keypair
            new_public_key = self.create_session(peer_id)
            
            # Clean up old session
            del old_session
            return new_public_key
        return None

    def _is_session_valid(self, peer_id):
        """Check if session is valid and not expired"""
        if peer_id not in self.sessions:
            return False
            
        session = self.sessions[peer_id]
        if time.time() - session['created_at'] > self.session_lifetime:
            logger.info(f"Session expired for peer: {peer_id}")
            del self.sessions[peer_id]
            return False
            
        return True and session['fernet'] is not None