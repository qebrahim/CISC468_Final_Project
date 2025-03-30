from pathlib import Path
import socket
import json
from crypto.auth import PeerAuthentication
import logging
import hashlib
from crypto.keys import generate_keypair, save_private_key, save_public_key, load_private_key, load_public_key


logger = logging.getLogger(__name__)
class Peer:
    def __init__(self, peer_id, address, keys_dir='keys'):
        self.peer_id = peer_id
        self.address = address
        self.connected_peers = {}
        
        self.keys_dir = Path(keys_dir).resolve()

        if not self.keys_dir.is_absolute():
            self.keys_dir = Path.home() / '.p2p-share' / keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        # Load or generate keys
        self.private_key = self.keys_dir / f'{peer_id}_private.pem'
        self.public_key = self.keys_dir / f'{peer_id}_public.pem'
        if not self.private_key.exists() or not self.public_key.exists():
            # Generate keys if not present
            private_key, public_key = generate_keypair()
            save_private_key(private_key, self.private_key)
            save_public_key(public_key, self.public_key)
        else:
            self.private_key = load_private_key(self.private_key)
            self.public_key = load_public_key(self.public_key)
        # Initialize authentication and session management
        

    def connect(self, peer):
        if peer.peer_id not in self.connected_peers:
            # Initiate mutual authentication
            auth_data = self.auth.initiate_authentication(
                peer.peer_id, 
                peer.auth.public_key
            )
            
            if auth_data:
                # Send authentication challenge to peer
                peer_response = peer.handle_auth_request(
                    self.peer_id,
                    auth_data['challenge'],
                    auth_data['signature'],
                    auth_data['public_key']
                )
                
                if peer_response and self.auth.verify_peer(
                    peer.peer_id,
                    peer_response['public_key'],
                    peer_response['challenge'],
                    peer_response['signature']
                ):
                    self.connected_peers[peer.peer_id] = peer
                    print(f"Connected and authenticated with peer: {peer.peer_id}")
                    return True
                else:
                    print(f"Authentication failed with peer: {peer.peer_id}")
                    return False
                    
        return False

    def disconnect(self, peer):
        if peer.peer_id in self.connected_peers:
            del self.connected_peers[peer.peer_id]
            print(f"Disconnected from peer: {peer.peer_id}")

    def send_file_request(self, peer_id, file_name):
        """Request a file from a peer with consent"""
        if peer_id not in self.connected_peers:
            logger.error(f"Peer {peer_id} not connected")
            return False
            
        try:
            peer = self.connected_peers[peer_id]
            logger.info(f"Requesting file '{file_name}' from peer: {peer_id}")
            # Encrypt file request using session key
            request_data = json.dumps({
                'file_name': file_name,
                'requester': self.peer_id
            }).encode()
            encrypted_request = self.auth.session_manager.encrypt_message(
                peer_id, 
                request_data
            )
            response = peer.handle_file_request(self.peer_id, file_name)
            # Decrypt response using session key
            decrypted_response = self.auth.session_manager.decrypt_message(
                peer_id,
                response
            )
            response_data = json.loads(decrypted_response)
            
            if response_data.get('status') == 'approved':

                # Create secure connection for file transfer
                host, port = peer.address.split(':')
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, int(port)))
                    
                    # Send authenticated request
                    request = {
                        'type': 'file_transfer',
                        'file_name': file_name,
                        'requester': self.peer_id,
                        'signature': self.auth.sign_message(file_name)
                    }
                    s.sendall(json.dumps(request).encode())
                    
                    # Receive and save file
                    file_path = self.shared_directory / file_name
                    file_hash = self.receive_file(s, file_path)
                    
                    # Verify file integrity
                    if file_hash == response['file_hash']:
                        logger.info(f"File '{file_name}' received and verified")
                        return True
                    else:
                        logger.error("File verification failed")
                        file_path.unlink()  # Remove corrupted file
                        return False
            else:
                logger.info("File request denied by peer")
                return False
                
        except Exception as e:
            logger.error(f"Error in file request: {e}")
            return False
    def handle_file_request(self, requester_id, file_name):
        """Handle incoming file request with consent"""
        if requester_id not in self.connected_peers:
            logger.error(f"Unverified peer {requester_id} requested file")
            return {'status': 'denied', 'reason': 'unauthorized'}
            
        file_path = self.shared_directory / file_name
        if not file_path.exists():
            return {'status': 'denied', 'reason': 'not_found'}
            
        # Ask for user consent
        consent = input(f"\nPeer {requester_id} requests file '{file_name}'. Allow? (y/n): ")
        if consent.lower() != 'y':
            return {'status': 'denied', 'reason': 'consent_denied'}
            
        # Calculate file hash for verification
        file_hash = self.calculate_file_hash(file_path)
        return {
            'status': 'approved',
            'file_hash': file_hash,
            'file_size': file_path.stat().st_size
        }
    def receive_file_request(self, peer_id, file_name):
        print(f"Received file request for '{file_name}' from peer: {peer_id}")
        try:
            file_path = self.shared_directory / file_name
            if file_path.exists():
                # Calculate file hash
                file_hash = self.calculate_file_hash(file_path)
                
                # Request user consent
                consent = input(f"Allow {peer_id} to download {file_name}? (y/n): ")
                if consent.lower() == 'y':
                    return {
                        'status': 'approved',
                        'file_hash': file_hash,
                        'file_size': file_path.stat().st_size
                    }
                else:
                    return {'status': 'denied'}
            else:
                return {'status': 'not_found'}
                
        except Exception as e:
            print(f"Error handling file request: {e}")
            return {'status': 'error', 'message': str(e)}

    def list_connected_peers(self):
        return list(self.connected_peers.keys())
    def receive_file(self, sock, file_path):
        """Receive file data and calculate hash"""
        sha256 = hashlib.sha256()
        with open(file_path, 'wb') as f:
            while True:
                data = sock.recv(8192)
                if not data:
                    break
                sha256.update(data)
                f.write(data)
        return sha256.hexdigest()

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    def migrate_keys(self):
        """Migrate to new keys and notify all connected peers"""
        try:
            # Initialize key migration
            migration_data = self.auth.initiate_key_migration()
            if not migration_data:
                return False
                
            # Notify all connected peers
            for peer_id, peer in self.connected_peers.items():
                try:
                    # Send migration notification
                    notification = {
                        'type': 'key_migration',
                        'peer_id': self.peer_id,
                        'new_public_key': migration_data['new_public_key'],
                        'migration_signature': migration_data['migration_signature']
                    }
                    
                    # Encrypt notification using current session key
                    encrypted_notification = self.auth.session_manager.encrypt_message(
                        peer_id,
                        json.dumps(notification).encode()
                    )
                    
                    # Send to peer
                    peer.handle_key_migration(encrypted_notification)
                    
                except Exception as e:
                    logger.error(f"Failed to notify peer {peer_id} of key migration: {e}")
                    
            # Switch to new keys
            self.auth.activate_new_keys()
            logger.info("Key migration completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Key migration failed: {e}")
            return False
            
    def handle_key_migration(self, encrypted_notification):
        """Handle a peer's key migration notification"""
        try:
            # Decrypt notification
            decrypted_data = self.auth.session_manager.decrypt_message(
                notification['peer_id'],
                encrypted_notification
            )
            notification = json.loads(decrypted_data)
            
            # Verify key migration
            if self.auth.verify_key_migration(
                notification['peer_id'],
                self.connected_peers[notification['peer_id']].auth.public_key,
                notification['new_public_key'],
                notification['migration_signature']
            ):
                logger.info(f"Accepted key migration from peer: {notification['peer_id']}")
                return True
            
            logger.error(f"Rejected key migration from peer: {notification['peer_id']}")
            return False
            
        except Exception as e:
            logger.error(f"Error handling key migration: {e}")
            return False