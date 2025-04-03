import os
import time
import base64
import json
import logging
from pathlib import Path
import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# Global registry of secure channels
secure_channels = {}

class SecureChannel:
    """
    Implements encrypted communication with forward secrecy using ECDHE
    (Elliptic Curve Diffie-Hellman Ephemeral) key exchange.
    """
    
    def __init__(self, peer_id, socket_conn=None, is_initiator=False):
        self.peer_id = peer_id
        self.socket = socket_conn
        self.is_initiator = is_initiator
        self.established = False
        self.session_id = None
        
        # Ephemeral key pair for this session
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        
        # Derived keys for encryption/decryption
        self.encryption_key = None
        self.decryption_key = None
        
        # Generate ephemeral key pair
        self._generate_ephemeral_keys()
        
        # Packet counter for IVs
        self.send_counter = 0
        self.receive_counter = 0
        
        logger.info(f"Secure channel created for peer {peer_id}")
    
    def _generate_ephemeral_keys(self):
        """Generate ephemeral EC key pair for this session"""
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
    
    def initiate_key_exchange(self):
        """Initiate the key exchange process (client side)"""
        if not self.socket:
            logger.error("No socket connection available")
            return False
        
        try:
            # Generate a unique session ID
            self.session_id = os.urandom(16).hex()
            
            # Create key exchange message
            key_exchange_msg = {
                "peer_id": self.peer_id,
                "session_id": self.session_id,
                "public_key": self.public_key_bytes.decode('utf-8')
            }
            
            # Send key exchange message
            self.socket.sendall(f"SECURE:EXCHANGE:{json.dumps(key_exchange_msg)}".encode('utf-8'))
            logger.info(f"Sent key exchange request to peer {self.peer_id}")
            
            # Wait for response (handled by protocol handler)
            return True
            
        except Exception as e:
            logger.error(f"Error initiating key exchange: {e}")
            return False
    
    def handle_key_exchange(self, exchange_data):
        """Handle key exchange message from peer"""
        try:
            peer_id = exchange_data.get("peer_id")
            session_id = exchange_data.get("session_id")
            peer_public_key_pem = exchange_data.get("public_key")
            
            if not peer_id or not session_id or not peer_public_key_pem:
                logger.error("Missing data in key exchange message")
                return False
            
            # Store the session ID
            self.session_id = session_id
            
            # Load peer's public key
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem.encode('utf-8'),
                default_backend()
            )
            
            # If we're the responder, send our public key back
            if not self.is_initiator:
                response = {
                    "peer_id": self.peer_id,
                    "session_id": self.session_id,
                    "public_key": self.public_key_bytes.decode('utf-8')
                }
                
                self.socket.sendall(f"SECURE:EXCHANGE_RESPONSE:{json.dumps(response)}".encode('utf-8'))
                logger.info(f"Sent key exchange response to peer {peer_id}")
            
            # Derive shared secret and encryption keys
            self._derive_shared_secret()
            
            # Mark the channel as established
            self.established = True
            
            # Add to global registry
            secure_channels[peer_id] = self
            
            logger.info(f"Secure channel established with peer {peer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling key exchange: {e}")
            return False
    
    def handle_exchange_response(self, response_data):
        """Handle exchange response from peer (client side)"""
        try:
            peer_id = response_data.get("peer_id")
            session_id = response_data.get("session_id")
            peer_public_key_pem = response_data.get("public_key")
            
            if not peer_id or not session_id or not peer_public_key_pem:
                logger.error("Missing data in exchange response")
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
            
            # Derive shared secret and encryption keys
            self._derive_shared_secret()
            
            # Mark the channel as established
            self.established = True
            
            # Add to global registry
            secure_channels[peer_id] = self
            
            logger.info(f"Secure channel established with peer {peer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling exchange response: {e}")
            return False
    
    def _derive_shared_secret(self):
        """Derive shared secret using ECDHE"""
        try:
            # Compute shared secret
            shared_secret = self.private_key.exchange(
                ec.ECDH(),
                self.peer_public_key
            )
            
            # Use HKDF to derive two separate keys for each direction
            # We use different info values to derive different keys for each direction
            if self.is_initiator:
                # Initiator uses first key for sending, second for receiving
                self.encryption_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,  # 256 bits for AES-256
                    salt=None,
                    info=b"initiator_to_responder"
                ).derive(shared_secret)
                
                self.decryption_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"responder_to_initiator"
                ).derive(shared_secret)
            else:
                # Responder uses first key for receiving, second for sending
                self.decryption_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"initiator_to_responder"
                ).derive(shared_secret)
                
                self.encryption_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"responder_to_initiator"
                ).derive(shared_secret)
            
            logger.debug("Derived encryption and decryption keys")
            
            # Clear the private key for forward secrecy
            # Once we've derived the shared secret, we don't need the private key anymore
            # This ensures forward secrecy even if the device is compromised later
            self.private_key = None
            
            return True
            
        except Exception as e:
            logger.error(f"Error deriving shared secret: {e}")
            return False
    
    def encrypt_message(self, plaintext):
        """Encrypt a message using AES-GCM"""
        if not self.established or not self.encryption_key:
            logger.error("Secure channel not established")
            return None
        
        try:
            # Generate a nonce using the counter (12 bytes)
            # We use a combination of session ID and counter to ensure uniqueness
            nonce = self.session_id[:8].encode('utf-8') + self.send_counter.to_bytes(4, byteorder='big')
            
            # Create an encryptor
            encryptor = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce),
                backend=default_backend()
            ).encryptor()
            
            # Add associated data (AAD) for authentication
            aad = f"{self.peer_id}:{self.session_id}:{self.send_counter}".encode('utf-8')
            encryptor.authenticate_additional_data(aad)
            
            # Encrypt the plaintext
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Get the tag
            tag = encryptor.tag
            
            # Increment the counter
            self.send_counter += 1
            
            # Format: base64(nonce) + ":" + base64(ciphertext) + ":" + base64(tag)
            encrypted_message = base64.b64encode(nonce).decode('utf-8') + ":" + \
                               base64.b64encode(ciphertext).decode('utf-8') + ":" + \
                               base64.b64encode(tag).decode('utf-8')
            
            return encrypted_message
            
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")
            return None
    
    def decrypt_message(self, encrypted_message):
        """Decrypt a message using AES-GCM"""
        if not self.established or not self.decryption_key:
            logger.error("Secure channel not established")
            return None
        
        try:
            # Parse the encrypted message
            parts = encrypted_message.split(":")
            if len(parts) != 3:
                logger.error("Invalid encrypted message format")
                return None
            
            nonce = base64.b64decode(parts[0])
            ciphertext = base64.b64decode(parts[1])
            tag = base64.b64decode(parts[2])
            
            # Create a decryptor
            decryptor = Cipher(
                algorithms.AES(self.decryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            
            # Add associated data (AAD) for authentication
            aad = f"{self.peer_id}:{self.session_id}:{self.receive_counter}".encode('utf-8')
            decryptor.authenticate_additional_data(aad)
            
            # Decrypt the ciphertext
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Increment the counter
            self.receive_counter += 1
            
            return plaintext
            
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            return None
    
    def send_encrypted(self, message_type, payload):
        """Send an encrypted message over the secure channel"""
        if not self.established:
            logger.error("Cannot send encrypted message - channel not established")
            return False
        
        try:
            # Construct the plaintext message
            plaintext = f"{message_type}:{payload}".encode('utf-8')
            
            # Encrypt the message
            encrypted = self.encrypt_message(plaintext)
            if not encrypted:
                logger.error(f"Failed to encrypt message of type {message_type}")
                return False
            
            # Send the encrypted message
            encrypted_message = f"SECURE:DATA:{encrypted}".encode('utf-8')
            logger.info(f"Sending encrypted message: Type={message_type}, Length={len(encrypted_message)}")
            
            self.socket.sendall(encrypted_message)
            return True
            
        except Exception as e:
            logger.error(f"Error sending encrypted message: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    
    def handle_encrypted_data(self, encrypted_data):
        """Handle an incoming encrypted message"""
        try:
            # Decrypt the message
            plaintext = self.decrypt_message(encrypted_data)
            if not plaintext:
                return None
            
            # Parse the plaintext message
            message = plaintext.decode('utf-8')
            parts = message.split(":", 1)
            
            if len(parts) != 2:
                logger.error("Invalid decrypted message format")
                return None
            
            message_type = parts[0]
            payload = parts[1]
            
            return {"type": message_type, "payload": payload}
            
        except Exception as e:
            logger.error(f"Error handling encrypted data: {e}")
            return None
    
    def close(self):
        """Close the secure channel"""
        try:
            if self.peer_id in secure_channels:
                del secure_channels[self.peer_id]
            
            # Clear sensitive data
            self.encryption_key = None
            self.decryption_key = None
            self.private_key = None
            self.peer_public_key = None
            
            self.established = False
            logger.info(f"Secure channel with peer {self.peer_id} closed")
            
        except Exception as e:
            logger.error(f"Error closing secure channel: {e}")


def create_secure_channel(peer_id, socket_conn=None, is_initiator=False):
    """Create a new secure channel for a peer"""
    channel = SecureChannel(peer_id, socket_conn, is_initiator)
    return channel

def get_secure_channel(peer_id):
    """Get an existing secure channel for a peer"""
    return secure_channels.get(peer_id)

def handle_secure_message(conn, addr, message):
    """Handle secure protocol messages"""
    try:
        parts = message.split(':', 2)
        if len(parts) < 3:
            logger.error(f"Invalid secure message format: {message}")
            return None
    
        secure_command = parts[1]
        payload = parts[2]

        # Add more detailed logging
        logger.info(f"Handling secure message: Command={secure_command}, Payload length={len(payload)}")

        # Unpack address (works for tuples or strings)
        if isinstance(addr, tuple):
            host, port = addr[0], addr[1]
        else:
            host, port = addr.split(':')

        standardAddr = f"{host}:12345"

        # Try to extract peer ID from the message payload
        extracted_peer_id = None
        try:
            if secure_command in ["EXCHANGE", "EXCHANGE_RESPONSE"]:
                exchange_data = json.loads(payload)
                extracted_peer_id = exchange_data.get("peer_id")
                logger.info(f"Extracted peer ID from payload: {extracted_peer_id}")
        except Exception as e:
            logger.error(f"Error extracting peer ID from payload: {e}")

        # Try to find contact by address
        from crypto import auth_protocol
        contact = auth_protocol.contact_manager.get_contact_by_address(standardAddr)
        
        if not contact:
            logger.error(f"No authenticated contact for {standardAddr}")
            
            # If we extracted a peer ID from the payload, try to use that
            if extracted_peer_id:
                logger.info(f"Attempting to use extracted peer ID: {extracted_peer_id}")
                contact = {"peer_id": extracted_peer_id}
            else:
                return {"status": "not_authenticated"}
        
        # Prioritize the extracted peer ID
        peer_id = extracted_peer_id or contact["peer_id"]
        logger.info(f"Using peer ID: {peer_id}")
        if not hasattr(handle_secure_message, 'conn_to_peer_id'):
            handle_secure_message.conn_to_peer_id = {}

        # The rest of the function remains the same as in the original implementation
        if secure_command == "EXCHANGE":
            # Handle key exchange request
            try:
                exchange_data = json.loads(payload)
                handle_secure_message.conn_to_peer_id[id(conn)] = peer_id

                
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
                response_data = json.loads(payload)
                
                # Find the channel
                channel = get_secure_channel(peer_id)
                if not channel:
                    logger.error(f"No pending secure channel for peer {peer_id}")
                    return {"status": "no_channel"}
                
                # Handle the exchange response
                if channel.handle_exchange_response(response_data):
                    return {"status": "secure_channel_established", "peer_id": peer_id}
                else:
                    return {"status": "exchange_failed"}
                    
            except Exception as e:
                logger.error(f"Error handling exchange response: {e}")
                return {"status": "error", "message": str(e)}
                
        elif secure_command == "DATA":
            # Handle encrypted data
            try:
                
                
                conn_id = id(conn)
                mapped_peer_id = handle_secure_message.conn_to_peer_id.get(conn_id)
            
                if mapped_peer_id:
                    logger.info(f"Using mapped peer ID for DATA: {mapped_peer_id}")
                    channel = get_secure_channel(mapped_peer_id)
                else:
                    logger.info(f"Using default peer ID: {peer_id}")
                    channel = get_secure_channel(peer_id)
                logger.debug(f"Channel lookup with peer_id: {peer_id}")
                logger.debug(f"Available secure channels: {list(secure_channels.keys())}")
                
                logger.debug(f"Looking for channel with peer_id: {peer_id}")
                logger.debug(f"Available channels: {list(secure_channels.keys())}")

                # Try alternative lookup methods:
                if channel is None:
                    for potential_id, potential_channel in secure_channels.items():
                        logger.debug(f"Comparing {potential_channel.socket} with {conn}")
                        if potential_channel.socket == conn:
                            logger.info(f"Found channel by socket match: {potential_id}")
                            channel = potential_channel
                            break
                
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
        logger.error(f"Comprehensive error in handle_secure_message: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

def encrypt_file(input_file, output_file, key):
    """Encrypt a file using AES-GCM"""
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

def decrypt_file(input_file, output_file, key):
    """Decrypt a file using AES-GCM"""
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

# Utility function to establish a secure channel with a peer
def establish_secure_channel(peer_id, peer_addr):
    """Establish a secure channel with a peer"""
    try:
        # Parse address
        if ":" in peer_addr:
            host, port_str = peer_addr.split(":")
            port = int(port_str)
        else:
            host = peer_addr
            port = 12345  # Default port
        
        # Create a new socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        # Create a secure channel
        channel = create_secure_channel(peer_id, sock, is_initiator=True)
        
        # Initiate key exchange
        if channel.initiate_key_exchange():
            logger.info(f"Key exchange initiated with peer {peer_id}")
            
            # The rest of the exchange will be handled by protocol.py
            # when the peer responds
            
            return {"status": "initiated", "channel": channel}
        else:
            sock.close()
            return {"status": "failed"}
            
    except Exception as e:
        logger.error(f"Error establishing secure channel: {e}")
        return {"status": "error", "message": str(e)}