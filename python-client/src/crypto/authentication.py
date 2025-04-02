import os
import time
import base64
import logging
import secrets
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

class PeerAuthentication:
    """Handles peer authentication using digital signatures"""
    
    def __init__(self, peer_id, contact_manager):
        self.peer_id = peer_id
        self.contact_manager = contact_manager
        self.storage_path = Path.home() / '.p2p-share' / 'keys'
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.private_key_path = self.storage_path / 'private.pem'
        self.public_key_path = self.storage_path / 'public.pem'
        
        # Load our own keys
        self.private_key = None
        self.public_key = None
        self.load_keys()
        
        # Track verification challenges
        self.pending_challenges = {}
        # Format: {challenge_id: {peer_id, challenge, timestamp}}
        
        logger.info(f"Authentication system initialized for peer {peer_id}")
    
    def load_keys(self):
        """Load the peer's own keys"""
        try:
            # Import the key functions only when needed
            from crypto.keys import load_private_key, load_public_key
            
            self.private_key = load_private_key(self.private_key_path)
            self.public_key = load_public_key(self.public_key_path)
            logger.info("Successfully loaded key pair")
            
            # Export public key in PEM format for sharing
            self.public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            return True
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            return False
    
    def get_public_key_pem(self):
        """Return our public key in PEM format for sharing"""
        return self.public_key_pem
    
    def create_challenge(self, peer_id):
        """Create a new authentication challenge for a peer"""
        challenge = secrets.token_bytes(32)  # 256-bit random challenge
        challenge_id = secrets.token_hex(8)  # Unique ID for this challenge
        challenge_b64 = base64.b64encode(challenge).decode('utf-8')
        
        # Store challenge for later verification
        self.pending_challenges[challenge_id] = {
            "peer_id": peer_id,
            "challenge": challenge,
            "timestamp": time.time()
        }
        
        # Clean up old challenges (older than 5 minutes)
        self._cleanup_challenges()
        
        return {
            "challenge_id": challenge_id,
            "challenge_b64": challenge_b64
        }
    
    def _cleanup_challenges(self):
        """Remove challenges older than 5 minutes"""
        current_time = time.time()
        expired_challenges = []
        
        for challenge_id, data in self.pending_challenges.items():
            if current_time - data["timestamp"] > 300:  # 5 minutes
                expired_challenges.append(challenge_id)
        
        for challenge_id in expired_challenges:
            del self.pending_challenges[challenge_id]
    
    def sign_challenge(self, challenge_b64):
        """Sign a challenge from another peer"""
        try:
            challenge = base64.b64decode(challenge_b64)
            
            # Create signature using our private key
            signature = self.private_key.sign(
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Return base64 encoded signature
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Error signing challenge: {e}")
            return None
    
    def verify_signature(self, peer_id, challenge_id, signature_b64):
        """Verify a peer's signature of our challenge"""
        try:
            # Get the challenge
            if challenge_id not in self.pending_challenges:
                logger.error(f"Challenge {challenge_id} not found or expired")
                return False
            
            challenge_data = self.pending_challenges[challenge_id]
            if challenge_data["peer_id"] != peer_id:
                logger.error(f"Challenge was not created for peer {peer_id}")
                return False
            
            # Get the peer's public key
            contact = self.contact_manager.get_trusted_contact(peer_id)
            if not contact:
                logger.error(f"No public key found for peer {peer_id}")
                return False
            
            # Load the peer's public key
            peer_public_key = serialization.load_pem_public_key(
                contact["public_key"].encode('utf-8')
            )
            
            # Decode the signature
            signature = base64.b64decode(signature_b64)
            
            # Verify the signature
            try:
                peer_public_key.verify(
                    signature,
                    challenge_data["challenge"],
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                # If we get here, the signature is valid
                logger.info(f"Successfully verified signature from peer {peer_id}")
                
                # Cleanup the challenge
                del self.pending_challenges[challenge_id]
                
                # Update last seen time
                self.contact_manager.update_last_seen(peer_id)
                
                return True
            except InvalidSignature:
                logger.warning(f"Invalid signature from peer {peer_id}")
                return False
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
    
    def load_peer_public_key(self, public_key_pem):
        """Load a peer's public key from PEM format"""
        try:
            return serialization.load_pem_public_key(
                public_key_pem.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Error loading peer public key: {e}")
            return None