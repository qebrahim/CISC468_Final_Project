import os
import time
import base64
import json
import logging
import socket
import hashlib
from pathlib import Path
from typing import Dict, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global registry of secure channels
secure_channels: Dict[str, 'SecureChannel'] = {}

class SecureChannel:
    """
    Implements encrypted communication with forward secrecy using ECDHE
    (Elliptic Curve Diffie-Hellman Ephemeral) key exchange.
    """
    
    def __init__(self, peer_id: str, socket_conn: Optional[socket.socket] = None, is_initiator: bool = False):
        """
        Initialize a secure channel with a specific peer.
        
        :param peer_id: Unique identifier for the peer
        :param socket_conn: Optional socket connection
        :param is_initiator: Whether this endpoint is initiating the connection
        """
        self.peer_id = peer_id
        self.socket = socket_conn
        self.is_initiator = is_initiator
        self.established = False
        self.session_id: Optional[str] = None
        
        # Ephemeral key pair for this session
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.peer_public_key: Optional[ec.EllipticCurvePublicKey] = None
        
        # Derived keys for encryption/decryption
        self.encryption_key: Optional[bytes] = None
        self.decryption_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None
        
        # Packet counter for IVs and replay protection
        self.send_counter = 0
        self.receive_counter = 0
        
        # Generate ephemeral key pair
        self._generate_ephemeral_keys()
        
        logger.info(f"Secure channel created for peer {peer_id}")
    
    def _generate_ephemeral_keys(self) -> None:
        """Generate ephemeral EC key pair for this session"""
        try:
            # Use NIST P-256 curve (comparable to secp256r1)
            self.private_key = ec.generate_private_key(
                ec.SECP256R1(),
                default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Serialize public key for transmission
            self.public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            logger.debug("Generated ephemeral EC key pair")
        except Exception as e:
            logger.error(f"Error generating ephemeral keys: {e}")
            raise
    
    def initiate_key_exchange(self) -> bool:
        """
        Initiate the key exchange process (client side)
        
        :return: True if key exchange initiated successfully, False otherwise
        """
        if not self.socket:
            logger.error("No socket connection available")
            return False
        
        try:
            # Generate a cryptographically secure session ID
            self.session_id = os.urandom(16).hex()
            
            # Create key exchange message
            key_exchange_msg = {
                "peer_id": self.peer_id,
                "session_id": self.session_id,
                "public_key": self.public_key_bytes.decode('utf-8')
            }
            
            # Send key exchange message
            full_message = f"SECURE:EXCHANGE:{json.dumps(key_exchange_msg)}"
            self.socket.sendall(full_message.encode('utf-8'))
            
            logger.info(f"Sent key exchange request to peer {self.peer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error initiating key exchange: {e}")
            return False
    
    def _derive_keys(self, shared_secret: bytes) -> None:
        """
        Derive encryption, decryption, and MAC keys using HKDF-like approach
        
        :param shared_secret: The shared secret derived from key exchange
        """
        try:
            # Define different info strings for each key derivation
            encryption_info = b"encryption_key"
            decryption_info = b"decryption_key"
            mac_info = b"mac_key"
            
            # Use a key derivation function with salt and info
            if self.is_initiator:
                # Initiator derives keys differently
                self.encryption_key = self._derive_subkey(shared_secret, encryption_info)
                self.decryption_key = self._derive_subkey(shared_secret, decryption_info)
                self.mac_key = self._derive_subkey(shared_secret, mac_info)
            else:
                # Responder derives keys differently
                self.decryption_key = self._derive_subkey(shared_secret, encryption_info)
                self.encryption_key = self._derive_subkey(shared_secret, decryption_info)
                self.mac_key = self._derive_subkey(shared_secret, mac_info)
            
            logger.debug("Successfully derived encryption, decryption, and MAC keys")
        except Exception as e:
            logger.error(f"Error deriving keys: {e}")
            raise
    
    def _derive_subkey(self, shared_secret: bytes, info: bytes, length: int = 32) -> bytes:
        """
        Derive a subkey using HKDF-like key derivation
        
        :param shared_secret: Base shared secret
        :param info: Context-specific info string
        :param length: Desired key length
        :return: Derived subkey
        """
        try:
            # Use PBKDF2 for key derivation with SHA-256
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=length,
                salt=info,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(shared_secret)
        except Exception as e:
            logger.error(f"Error deriving subkey: {e}")
            raise
    
    def handle_key_exchange(self, exchange_data: Dict[str, str]) -> bool:
        """
        Handle key exchange message from peer
        
        :param exchange_data: Key exchange message data
        :return: True if key exchange successful, False otherwise
        """
        try:
            # Extract and validate exchange data
            peer_id = exchange_data.get("peer_id")
            session_id = exchange_data.get("session_id")
            peer_public_key_pem = exchange_data.get("public_key")
            
            if not all([peer_id, session_id, peer_public_key_pem]):
                logger.error("Missing data in key exchange message")
                return False
            
            # Store the session ID
            self.session_id = session_id
            
            # Load peer's public key
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem.encode('utf-8'),
                default_backend()
            )
            
            # Compute shared secret using ECDH
            shared_secret = self.private_key.exchange(
                ec.ECDH(), 
                self.peer_public_key
            )
            
            # Derive encryption keys
            self._derive_keys(shared_secret)
            
            # If we're the responder, send our public key back
            if not self.is_initiator and self.socket:
                response = {
                    "peer_id": self.peer_id,
                    "session_id": self.session_id,
                    "public_key": self.public_key_bytes.decode('utf-8')
                }
                
                response_message = f"SECURE:EXCHANGE_RESPONSE:{json.dumps(response)}"
                self.socket.sendall(response_message.encode('utf-8'))
                logger.info(f"Sent key exchange response to peer {peer_id}")
            
            # Mark the channel as established
            self.established = True
            
            # Add to global registry
            secure_channels[peer_id] = self
            
            logger.info(f"Secure channel established with peer {peer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling key exchange: {e}")
            return False
    
    def handle_exchange_response(self, response_data: Dict[str, str]) -> bool:
        """
        Handle exchange response from peer (client side)
        
        :param response_data: Response data from the peer
        :return: True if response handled successfully, False otherwise
        """
        try:
            # Extract and validate response data
            peer_id = response_data.get("peer_id")
            session_id = response_data.get("session_id")
            peer_public_key_pem = response_data.get("public_key")
            
            if not all([peer_id, session_id, peer_public_key_pem]):
                logger.error("Missing required data in exchange response")
                return False
            
            # Verify session ID matches
            if session_id != self.session_id:
                logger.error(f"Session ID mismatch: expected {self.session_id}, got {session_id}")
                return False
            
            # Load peer's public key
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem.encode('utf-8'),
                default_backend()
            )
            
            # Compute shared secret using ECDH
            shared_secret = self.private_key.exchange(
                ec.ECDH(), 
                self.peer_public_key
            )
            
            # Derive encryption keys
            self._derive_keys(shared_secret)
            
            # Mark the channel as established
            self.established = True
            
            # Add to global registry
            secure_channels[peer_id] = self
            
            logger.info(f"Secure channel established with peer {peer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling exchange response: {e}")
            return False
    
    def encrypt_message(self, plaintext: Union[str, bytes]) -> Optional[str]:
        """
        Encrypt a message using AES-CBC with HMAC for authentication
        
        :param plaintext: Message to encrypt
        :return: Base64 encoded encrypted message or None if encryption fails
        """
        if not self.established or not self.encryption_key:
            logger.error("Secure channel not established")
            return None
        
        try:
            # Ensure plaintext is bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate IV (16 bytes for CBC)
            iv = os.urandom(16)
            
            # Pad the plaintext using PKCS7
            block_size = 16
            padding_length = block_size - (len(plaintext) % block_size)
            if padding_length == 0:
                padding_length = block_size
                
            padding = bytes([padding_length]) * padding_length
            padded_data = plaintext + padding
            
            # Create AES-CBC cipher
            encryptor = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            ).encryptor()
            
            # Encrypt the padded data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Compute HMAC for authentication
            h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            mac = h.finalize()
            
            # Increment counter
            self.send_counter += 1
            
            # Format: base64(iv) + ":" + base64(ciphertext) + ":" + base64(mac)
            encrypted_message = (
                f"{base64.b64encode(iv).decode('utf-8')}:"
                f"{base64.b64encode(ciphertext).decode('utf-8')}:"
                f"{base64.b64encode(mac).decode('utf-8')}"
            )
            
            return encrypted_message
            
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")
            return None
    
    def decrypt_message(self, encrypted_message: str) -> Optional[bytes]:
        """
        Decrypt a message using AES-CBC with HMAC verification
        
        :param encrypted_message: Encrypted message string
        :return: Decrypted message or None if decryption fails
        """
        if not self.established or not self.decryption_key:
            logger.error("Secure channel not established")
            return None
        
        try:
            # Parse the encrypted message
            parts = encrypted_message.split(":")
            if len(parts) != 3:
                logger.error(f"Invalid encrypted message format: expected 3 parts, got {len(parts)}")
                return None
                
            # Extract and decode IV, ciphertext, and MAC
            iv = base64.b64decode(parts[0])
            ciphertext = base64.b64decode(parts[1])
            received_mac = base64.b64decode(parts[2])
            
            # Verify MAC
            h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            try:
                h.verify(received_mac)
            except Exception:
                logger.error("MAC verification failed - message may have been tampered with")
                return None
            
            # Create AES-CBC decryptor
            decryptor = Cipher(
                algorithms.AES(self.decryption_key),
                modes.CBC(iv),
                backend=default_backend()
            ).decryptor()
            
            # Decrypt the data
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = plaintext_padded[-1]
            
            # Validate padding
            if padding_length == 0 or padding_length > 16:
                logger.error(f"Invalid padding length: {padding_length}")
                return None
                
            # Verify padding bytes
            for i in range(1, padding_length + 1):
                if plaintext_padded[-i] != padding_length:
                    logger.error("Invalid padding bytes")
                    return None
                    
            plaintext = plaintext_padded[:-padding_length]
            
            # Increment receive counter
            self.receive_counter += 1
            
            return plaintext
                
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            return None
    
    def handle_encrypted_data(self, encrypted_data: str) -> Optional[Dict[str, str]]:
        """
        Handle an incoming encrypted message
        
        :param encrypted_data: Encrypted message
        :return: Decrypted message dictionary or None if processing fails
        """
        try:
            # Decrypt the message
            plaintext = self.decrypt_message(encrypted_data)
            if not plaintext:
                logger.error("Failed to decrypt message")
                return None
            
            # Try to decode as UTF-8
            try:
                message = plaintext.decode('utf-8')
            except UnicodeDecodeError as e:
                logger.error(f"Failed to decode plaintext as UTF-8: {e}")
                logger.error(f"Raw plaintext (hex): {plaintext.hex()}")
                return None
            
            # Parse the plaintext message
            parts = message.split(":", 1)
            
            if len(parts) != 2:
                logger.error(f"Invalid decrypted message format. Message: '{message}'")
                return None
            
            message_type = parts[0]
            payload = parts[1]
            
            logger.info(f"Successfully handled encrypted message of type: {message_type}")
            return {"type": message_type, "payload": payload}
            
        except Exception as e:
            logger.error(f"Error handling encrypted data: {e}")
            return None
    
    def send_encrypted_message(self, message_type: str, payload: str) -> bool:
        """
        Send an encrypted message through the secure channel
        
        :param message_type: Type of message
        :param payload: Message payload
        :return: True if message sent successfully, False otherwise
        """
        if not self.established or not self.socket:
            logger.error("Secure channel not established or no socket available")
            return False
        
        try:
            # Construct the message
            full_message = f"{message_type}:{payload}"
            
            # Encrypt the message
            encrypted_message = self.encrypt_message(full_message)
            if not encrypted_message:
                logger.error("Failed to encrypt message")
                return False
            
            # Send the encrypted message
            secure_message = f"SECURE:DATA:{encrypted_message}"
            self.socket.sendall(secure_message.encode('utf-8'))
            
            logger.info(f"Sent encrypted message of type: {message_type}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending encrypted message: {e}")
            return False
    
    def close(self) -> None:
        """
        Close the secure channel and clean up resources
        """
        try:
            # Remove from global registry
            if self.peer_id in secure_channels:
                del secure_channels[self.peer_id]
            
            # Clear sensitive data
            self.encryption_key = None
            self.decryption_key = None
            self.mac_key = None
            self.private_key = None
            self.peer_public_key = None
            
            # Close socket if it exists
            if self.socket:
                try:
                    self.socket.close()
                except Exception as socket_close_err:
                    logger.error(f"Error closing socket: {socket_close_err}")
            
            # Reset channel state
            self.established = False
            self.session_id = None
            
            logger.info(f"Secure channel with peer {self.peer_id} closed")
            
        except Exception as e:
            logger.error(f"Error closing secure channel: {e}")

# Utility functions
def create_secure_channel(
    peer_id: str, 
    socket_conn: Optional[socket.socket] = None, 
    is_initiator: bool = False
) -> SecureChannel:
    """
    Create a new secure channel for a peer
    
    :param peer_id: Unique identifier for the peer
    :param socket_conn: Optional socket connection
    :param is_initiator: Whether this endpoint is initiating the connection
    :return: Newly created SecureChannel instance
    """
    return SecureChannel(peer_id, socket_conn, is_initiator)

def get_secure_channel(peer_id: str) -> Optional[SecureChannel]:
    """
    Get an existing secure channel for a peer
    
    :param peer_id: Peer identifier
    :return: Existing SecureChannel or None
    """
    return secure_channels.get(peer_id)

def handle_secure_message(
    conn: socket.socket, 
    addr: Union[str, tuple], 
    message: str
) -> Dict[str, Union[str, bool]]:
    """
    Handle secure protocol messages
    
    :param conn: Socket connection
    :param addr: Address of the peer
    :param message: Secure protocol message
    :return: Dictionary with processing result
    """
    try:
        # Split the message
        parts = message.split(':', 2)
        if len(parts) < 3:
            logger.error(f"Invalid secure message format: {message}")
            return {"status": "error", "message": "Invalid message format"}
    
        secure_command = parts[1]
        payload = parts[2]

        # Add more detailed logging
        logger.info(f"Handling secure message: Command={secure_command}, Payload length={len(payload)}")

        # Unpack address (works for tuples or strings)
        if isinstance(addr, tuple):
            host, port = addr[0], addr[1]
        else:
            host, port = addr.split(':')

        # Default to standard port if needed
        standardAddr = f"{host}:12345"

        # Attempt to parse payload
        try:
            exchange_data = json.loads(payload)
        except json.JSONDecodeError:
            logger.error("Failed to parse payload JSON")
            return {"status": "error", "message": "Invalid payload JSON"}

        # Try to extract peer ID
        peer_id = exchange_data.get("peer_id")
        if not peer_id:
            logger.error("No peer ID found in payload")
            return {"status": "not_authenticated", "message": "Missing peer ID"}

        # Process different secure commands
        if secure_command == "EXCHANGE":
            # Handle key exchange request
            try:
                # Create a new secure channel as responder
                channel = create_secure_channel(peer_id, conn, is_initiator=False)
                
                # Handle the exchange
                if channel.handle_key_exchange(exchange_data):
                    return {"status": "secure_channel_established", "peer_id": peer_id}
                else:
                    return {"status": "exchange_failed"}
                    
            except Exception as e:
                logger.error(f"Error handling key exchange: {e}")
                return {"status": "error", "message": str(e)}
                
        elif secure_command == "EXCHANGE_RESPONSE":
            # Handle key exchange response
            try:
                # Find the channel
                channel = get_secure_channel(peer_id)
                if not channel:
                    logger.error(f"No pending secure channel for peer {peer_id}")
                    return {"status": "no_channel"}
                
                # Handle the exchange response
                if channel.handle_exchange_response(exchange_data):
                    return {"status": "secure_channel_established", "peer_id": peer_id}
                else:
                    return {"status": "exchange_failed"}
                    
            except Exception as e:
                logger.error(f"Error handling exchange response: {e}")
                return {"status": "error", "message": str(e)}
                
        elif secure_command == "DATA":
            # Handle encrypted data
            try:
                # Try to find the channel
                channel = get_secure_channel(peer_id)
                
                if not channel:
                    logger.error(f"No secure channel established for peer {peer_id}")
                    return {"status": "no_secure_channel"}
                
                # Decrypt and handle the data
                result = channel.handle_encrypted_data(payload)
                if result:
                    return {
                        "status": "message_received",
                        "peer_id": peer_id,
                        "type": result["type"],
                        "payload": result["payload"]
                    }
                else:
                    return {"status": "decryption_failed"}
                    
            except Exception as e:
                logger.error(f"Error handling encrypted data: {e}")
                return {"status": "error", "message": str(e)}
        else:
            logger.error(f"Unknown secure command: {secure_command}")
            return {"status": "unknown_command"}
    except Exception as e:
        logger.error(f"Error handling secure message: {e}")
        return {"status": "error", "message": str(e)}

def establish_secure_channel(
    peer_id: str, 
    peer_addr: str, 
    port: int = 12345
) -> Dict[str, Union[str, SecureChannel]]:
    """
    Establish a secure channel with a peer
    
    :param peer_id: Unique identifier for the peer
    :param peer_addr: IP address or hostname of the peer
    :param port: Port number to connect to
    :return: Dictionary with connection status and channel
    """
    try:
        # Create a new socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer_addr, port))
        
        # Create a secure channel
        channel = create_secure_channel(peer_id, sock, is_initiator=True)
        
        # Initiate key exchange
        if channel.initiate_key_exchange():
            logger.info(f"Key exchange initiated with peer {peer_id}")
            
            return {
                "status": "initiated", 
                "channel": channel
            }
        else:
            sock.close()
            return {"status": "failed"}
            
    except Exception as e:
        logger.error(f"Error establishing secure channel: {e}")
        return {
            "status": "error", 
            "message": str(e)
        }

# File encryption utilities
def encrypt_file(input_file: str, output_file: str, key: bytes) -> bool:
    """
    Encrypt a file using AES-GCM
    
    :param input_file: Path to the input file
    :param output_file: Path to the output encrypted file
    :param key: Encryption key
    :return: True if encryption successful, False otherwise
    """
    try:
        # Generate a random 96-bit IV
        iv = os.urandom(12)
        
        # Create an encryptor
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # Read the input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Encrypt the file
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Get the tag
        tag = encryptor.tag
        
        # Write IV, tag, and ciphertext to output file
        with open(output_file, 'wb') as f:
            f.write(iv)
            f.write(tag)
            f.write(ciphertext)
        
        return True
        
    except Exception as e:
        logger.error(f"Error encrypting file: {e}")
        return False

def decrypt_file(input_file: str, output_file: str, key: bytes) -> bool:
    """
    Decrypt a file using AES-GCM
    
    :param input_file: Path to the encrypted input file
    :param output_file: Path to the decrypted output file
    :param key: Decryption key
    :return: True if decryption successful, False otherwise
    """
    try:
        # Read the encrypted file
        with open(input_file, 'rb') as f:
            # First 12 bytes are IV
            iv = f.read(12)
            # Next 16 bytes are tag
            tag = f.read(16)
            # Rest is ciphertext
            ciphertext = f.read()
        
        # Create a decryptor
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        # Decrypt the file
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Write the decrypted data to output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        return True
        
    except Exception as e:
        logger.error(f"Error decrypting file: {e}")
        return False