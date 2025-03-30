from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from .keys import load_private_key, load_public_key, generate_keypair, save_private_key, save_public_key
import os
import time
from .session import SessionManager
import logging



logger = logging.getLogger(__name__)
class PeerAuthentication:
    def __init__(self, peer_id, keys_dir):
        self.peer_id = peer_id
        self.keys_dir = keys_dir
        self.private_key = load_private_key(self.keys_dir / 'private.pem')
        self.public_key = load_public_key(self.keys_dir / 'public.pem')
        self.verified_peers = {}
        self.session_manager = SessionManager()


    def initiate_authentication(self, peer_id, peer_public_key):
        """Start mutual authentication process"""
        try:
            
            dh_public_key = self.session_manager.create_session(peer_id)

            # Generate and sign challenge
            challenge = self.generate_challenge()
            signature = self.sign_message(challenge)
            
            return {
                'peer_id': self.peer_id,
                'challenge': challenge,
                'signature': signature,
                'public_key': self.public_key,
                'dh_public_key': dh_public_key  # Add DH public key

            }
        except Exception as e:
            print(f"Authentication initiation failed: {e}")
            return None
    
    def verify_peer(self, peer_id, peer_public_key, challenge, signature, dh_public_key):
        """Verify peer's identity and establish session"""
        try:
            if self.verify_signature(peer_public_key, challenge, signature):
                # Complete session setup
                self.session_manager.complete_session(peer_id, dh_public_key)
                
                # Store verified peer information
                self.verified_peers[peer_id] = {
                    'public_key': peer_public_key,
                    'verified_at': time.time()
                }
                return True
            return False
        except Exception as e:
            print(f"Peer verification failed: {e}")
            return False

    def generate_challenge(self):
        """Generate random challenge for authentication"""
        return os.urandom(32).hex()

    def sign_message(self, message):
        """Sign a message using private key"""
        return self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, public_key, message, signature):
        """Verify a signature using public key"""
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    def initiate_key_migration(self):
        """Generate new keys and create migration signature"""
        try:
            # Generate new keypair
            new_private_key, new_public_key = generate_keypair()
            
            # Sign the new public key with the old private key
            migration_signature = self.private_key.sign(
                new_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Save new keys
            save_private_key(new_private_key, self.keys_dir / f'{self.peer_id}_private_new.pem')
            save_public_key(new_public_key, self.keys_dir / f'{self.peer_id}_public_new.pem')
            
            return {
                'new_public_key': new_public_key,
                'migration_signature': migration_signature
            }
            
        except Exception as e:
            logger.error(f"Key migration failed: {e}")
            return None

    def verify_key_migration(self, peer_id, old_public_key, new_public_key, migration_signature):
        """Verify a peer's key migration request"""
        try:
            # Verify the migration signature using old key
            old_public_key.verify(
                migration_signature,
                new_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Update peer's public key
            self.verified_peers[peer_id]['public_key'] = new_public_key
            self.verified_peers[peer_id]['migration_time'] = time.time()
            
            # Rotate session for this peer
            self.session_manager.rotate_session(peer_id)
            
            return True
            
        except InvalidSignature:
            logger.error(f"Invalid key migration signature from peer: {peer_id}")
            return False
        except Exception as e:
            logger.error(f"Key migration verification failed: {e}")
            return False
    
    def handle_auth_request(self, peer_id, challenge, signature, public_key):
        """Handle authentication request from another peer"""
        try:
            if self.verify_signature(public_key, challenge, signature):
                # Generate response challenge
                response_challenge = self.generate_challenge()
                response_signature = self.sign_message(response_challenge)
                
                return {
                    'peer_id': self.peer_id,
                    'challenge': response_challenge,
                    'signature': response_signature,
                    'public_key': self.public_key
                }
            return None
        except Exception as e:
            logger.error(f"Auth request handling failed: {e}")
            return None

    def activate_new_keys(self):
        """Activate newly generated keys after successful migration"""
        try:
            # Backup old keys with timestamp
            timestamp = int(time.time())
            backup_dir = self.keys_dir / 'backup'
            backup_dir.mkdir(exist_ok=True)
            
            old_private_backup = backup_dir / f'private_{timestamp}.pem'
            old_public_backup = backup_dir / f'public_{timestamp}.pem'
            
            # Save backup of old keys
            save_private_key(self.private_key, old_private_backup)
            save_public_key(self.public_key, old_public_backup)
            
            # Load new keys
            new_private_path = self.keys_dir / f'{self.peer_id}_private_new.pem'
            new_public_path = self.keys_dir / f'{self.peer_id}_public_new.pem'
            
            if not new_private_path.exists() or not new_public_path.exists():
                raise FileNotFoundError("New keys not found")
                
            # Activate new keys
            self.private_key = load_private_key(new_private_path)
            self.public_key = load_public_key(new_public_path)
            
            # Move new keys to primary location
            save_private_key(self.private_key, self.keys_dir / 'private.pem')
            save_public_key(self.public_key, self.keys_dir / 'public.pem')
            
            # Clean up temporary files
            new_private_path.unlink()
            new_public_path.unlink()
            
            logger.info("Successfully activated new keys")
            return True
            
        except Exception as e:
            logger.error(f"Failed to activate new keys: {e}")
            return False