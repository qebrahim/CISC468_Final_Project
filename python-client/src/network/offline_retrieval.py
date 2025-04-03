import os
import json
import socket
import hashlib
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

class OfflineFileRequest:
    """Represents a request to find a file from alternative peers when original owner is offline"""
    
    def __init__(self, file_name, original_peer_id, requester_peer_id, expected_hash=None):
        self.file_name = file_name
        self.original_peer_id = original_peer_id
        self.requester_peer_id = requester_peer_id
        self.expected_hash = expected_hash
        self.timestamp = time.time()
    
    def to_json(self):
        """Convert to JSON string"""
        data = {
            "file_name": self.file_name,
            "original_peer_id": self.original_peer_id,
            "requester_peer_id": self.requester_peer_id,
            "expected_hash": self.expected_hash,
            "timestamp": self.timestamp
        }
        return json.dumps(data)
    
    @classmethod
    def from_json(cls, json_str):
        """Create from JSON string"""
        data = json.loads(json_str)
        request = cls(
            data["file_name"],
            data["original_peer_id"],
            data["requester_peer_id"],
            data.get("expected_hash")
        )
        request.timestamp = data.get("timestamp", time.time())
        return request


class OfflineFileResponse:
    """Represents a response to an offline file request"""
    
    def __init__(self, file_name, peer_id, has_file=False, can_share=False, 
                 hash=None, peer_address=None, error_message=None):
        self.file_name = file_name
        self.peer_id = peer_id
        self.has_file = has_file
        self.can_share = can_share
        self.hash = hash
        self.peer_address = peer_address
        self.error_message = error_message
    
    def to_json(self):
        """Convert to JSON string"""
        data = {
            "file_name": self.file_name,
            "peer_id": self.peer_id,
            "has_file": self.has_file,
            "can_share": self.can_share,
            "hash": self.hash,
            "peer_address": self.peer_address,
            "error_message": self.error_message
        }
        return json.dumps(data)
    
    @classmethod
    def from_json(cls, json_str):
        """Create from JSON string"""
        data = json.loads(json_str)
        return cls(
            data["file_name"],
            data["peer_id"],
            data.get("has_file", False),
            data.get("can_share", False),
            data.get("hash"),
            data.get("peer_address"),
            data.get("error_message")
        )


def request_file_from_alternative(file_name, original_peer_id, requester_peer_id, expected_hash=None, 
                                  contact_manager=None):
    """
    Attempt to find and request a file from an alternative peer when the original peer is offline
    
    Args:
        file_name: Name of the file to request
        original_peer_id: ID of the original peer that should have the file
        requester_peer_id: ID of the requester (us)
        expected_hash: Expected hash of the file for verification
        contact_manager: The contact manager for looking up trusted peers
        
    Returns:
        tuple: (success, alternative_peer_id, error_message)
    """
    try:
        logger.info(f"Looking for alternative sources for file: {file_name}")
        logger.info(f"Original peer {original_peer_id} appears to be offline")
        
        # Validate that we have a contact manager
        if contact_manager is None:
            return False, None, "Contact manager not available"
        
        # Get all trusted contacts
        contacts = contact_manager.get_all_trusted_contacts()
        if not contacts:
            return False, None, "No trusted contacts available to check for the file"
        
        print(f"Checking {len(contacts)} trusted peers for file: {file_name}")
        
        # Create the offline file request
        request = OfflineFileRequest(file_name, original_peer_id, requester_peer_id, expected_hash)
        request_json = request.to_json()
        
        # Query all trusted contacts to find alternatives
        alternative_peers = []
        
        for peer_id, contact in contacts.items():
            # Skip the original peer which we know is offline
            if peer_id == original_peer_id:
                continue
            
            # Skip ourselves
            if peer_id == requester_peer_id:
                continue
            
            # Try to connect to this peer
            addr = contact.get("address")
            if not addr or ":" not in addr:
                logger.warning(f"Invalid address format for peer {peer_id}: {addr}")
                continue
            
            host, port_str = addr.split(":")
            try:
                port = int(port_str)
            except ValueError:
                logger.warning(f"Invalid port in address for peer {peer_id}: {addr}")
                continue
            
            print(f"Checking peer {peer_id} at {addr} for file: {file_name}")
            
            try:
                # Connect to the peer with timeout
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)  # 5 second timeout
                sock.connect((host, port))
                
                # Send offline file request
                sock.sendall(f"OFFLINE_FILE_REQUEST:{request_json}".encode('utf-8'))
                
                # Wait for response with timeout
                sock.settimeout(10)  # 10 second timeout for response
                try:
                    response_data = sock.recv(4096).decode('utf-8')
                    
                    if response_data.startswith("OFFLINE_FILE_RESPONSE:"):
                        response_json = response_data[len("OFFLINE_FILE_RESPONSE:"):]
                        response = OfflineFileResponse.from_json(response_json)
                        
                        if response.has_file and response.can_share:
                            print(f"Peer {peer_id} has the file and is willing to share")
                            alternative_peers.append(response)
                        elif response.has_file:
                            print(f"Peer {peer_id} has the file but cannot share at this time")
                        else:
                            print(f"Peer {peer_id} does not have the file")
                    else:
                        print(f"Unexpected response from {peer_id}: {response_data[:50]}")
                
                except socket.timeout:
                    print(f"No response from {peer_id} (timeout)")
                
                sock.close()
                
            except Exception as e:
                logger.warning(f"Error connecting to peer {peer_id}: {e}")
                print(f"Peer {peer_id} is not available: {e}")
        
        # Check if we found any alternative sources
        if not alternative_peers:
            return False, None, f"No alternative sources found for file {file_name}"
        
        # Select the first available alternative (could be improved with more sophisticated selection)
        selected_peer = alternative_peers[0]
        print(f"Selected peer {selected_peer.peer_id} as alternative source for file {file_name}")
        
        # Request the file from the selected peer
        success = request_file_from_peer(
            selected_peer.peer_address, 
            file_name, 
            expected_hash if expected_hash else selected_peer.hash
        )
        
        if success:
            return True, selected_peer.peer_id, None
        else:
            return False, None, "Failed to retrieve file from alternative peer"
        
    except Exception as e:
        logger.error(f"Error in offline file retrieval: {e}")
        return False, None, f"Error: {str(e)}"


def request_file_from_peer(peer_addr, file_name, expected_hash=None):
    """
    Request a file from a specific peer with expected hash verification
    
    Args:
        peer_addr: Address of the peer (host:port)
        file_name: Name of the file to request
        expected_hash: Expected hash of the file for verification
        
    Returns:
        bool: True if the file was successfully retrieved
    """
    try:
        # Parse address
        if ":" not in peer_addr:
            return False
        
        host, port_str = peer_addr.split(":")
        try:
            port = int(port_str)
        except ValueError:
            logger.error(f"Invalid port in peer address: {peer_addr}")
            return False
        
        print(f"Requesting file '{file_name}' from alternative peer {peer_addr}")
        
        # Create a new connection for the file request
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5 second connection timeout
        sock.connect((host, port))
        
        # Send file request
        request_msg = f"REQUEST_FILE:{file_name}"
        sock.sendall(request_msg.encode('utf-8'))
        
        # Set response timeout
        sock.settimeout(30)  # 30 second timeout for response
        
        # Read response header
        header_data = sock.recv(1024).decode('utf-8')
        
        if header_data.startswith("ERR"):
            logger.error(f"Error from peer: {header_data}")
            sock.close()
            return False
        
        # Check for file data header
        if not header_data.startswith("FILE_DATA:"):
            logger.error(f"Unexpected response: {header_data[:50]}")
            sock.close()
            return False
        
        # Parse file header
        parts = header_data.split(":")
        if len(parts) < 3:
            logger.error("Invalid file header format")
            sock.close()
            return False
        
        received_file_name = parts[1]
        
        try:
            file_size = int(parts[2])
        except ValueError:
            logger.error(f"Invalid file size in header: {parts[2]}")
            sock.close()
            return False
        
        # Check for hash in header
        received_hash = None
        if len(parts) > 3 and parts[3]:
            received_hash = parts[3]
        
        # If we have an expected hash and a received hash, compare them
        if expected_hash and received_hash and expected_hash != received_hash:
            logger.error(f"File hash mismatch: expected {expected_hash}, got {received_hash}")
            sock.close()
            return False
        
        print(f"Receiving file {received_file_name} ({file_size} bytes) from alternative peer")
        
        # Create output directory
        output_dir = Path.home() / '.p2p-share' / 'shared'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / received_file_name
        
        # Calculate header length to determine if we already have some file data
        header_prefix = "FILE_DATA:"
        header_length = len(header_prefix) + len(received_file_name) + 1 + len(str(file_size)) + 1
        if received_hash:
            header_length += len(received_hash) + 1
        
        # Initialize hasher for verification
        hasher = hashlib.sha256()
        
        # Extract any file data already received in the header message
        initial_data = b''
        if len(header_data) > header_length:
            initial_data = header_data[header_length:].encode('utf-8')
            if initial_data:
                hasher.update(initial_data)
        
        # Open output file and write initial data if any
        with open(output_path, 'wb') as f:
            if initial_data:
                f.write(initial_data)
            
            # Calculate bytes received so far
            bytes_received = len(initial_data)
            
            # Download the rest of the file
            sock.settimeout(60)  # Longer timeout for file transfer
            
            while bytes_received < file_size:
                # Read in chunks
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    
                    f.write(chunk)
                    hasher.update(chunk)
                    bytes_received += len(chunk)
                    
                    # Display progress
                    percent = (bytes_received / file_size) * 100
                    print(f"Download progress: {percent:.1f}%", end='\r')
                    
                except socket.timeout:
                    logger.error("Socket timeout during file transfer")
                    break
            
            print()  # New line after progress display
            
            # If we didn't get the full file, warn the user
            if bytes_received < file_size:
                print(f"Warning: Only received {bytes_received} of {file_size} bytes")
                
                # Ask user if they want to keep the partial file
                print("Keep incomplete file? (y/n): ", end="")
                answer = input().lower()
                if answer != 'y':
                    os.remove(output_path)
                    print("Incomplete file deleted")
                    sock.close()
                    return False
            
            # Verify hash if expected
            if expected_hash:
                calculated_hash = hasher.hexdigest()
                
                if calculated_hash != expected_hash:
                    print(f"Hash verification failed: expected {expected_hash}, got {calculated_hash}")
                    
                    # Ask user if they want to keep the file despite hash mismatch
                    print("Keep file despite hash mismatch? (y/n): ", end="")
                    answer = input().lower()
                    if answer != 'y':
                        os.remove(output_path)
                        print("File deleted due to hash mismatch")
                        sock.close()
                        return False
                else:
                    print("File hash verified successfully ✓")
        
        sock.close()
        print(f"File downloaded successfully to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error requesting file from peer: {e}")
        return False


def handle_offline_file_request(conn, addr, request_json, peer_id, hash_manager=None):
    """
    Handle a request for a file when the original owner is offline
    
    Args:
        conn: The connection socket
        addr: The peer's address
        request_json: The JSON string containing the request
        peer_id: Our peer ID
        hash_manager: Optional hash manager for verifying file integrity
    """
    try:
        # Parse the request
        request = OfflineFileRequest.from_json(request_json)
        
        print(f"\nReceived offline file request for: {request.file_name} (originally from peer {request.original_peer_id})")
        
        # Check if we have the file
        shared_dir = Path.home() / '.p2p-share' / 'shared'
        file_path = shared_dir / request.file_name
        
        has_file = file_path.exists()
        file_hash = None
        
        if has_file:
            # Calculate file hash for verification
            if request.expected_hash or hash_manager:
                file_hash = calculate_file_hash(file_path)
                
                # If hash doesn't match expected hash, we don't have the right file
                if request.expected_hash and file_hash != request.expected_hash:
                    print(f"File hash mismatch: expected {request.expected_hash}, got {file_hash}")
                    has_file = False
        
        if not has_file:
            response = OfflineFileResponse(
                request.file_name,
                peer_id,
                has_file=False,
                can_share=False
            )
            send_offline_file_response(conn, response)
            return
        
        # Ask user for consent to share the file
        print(f"Peer {request.requester_peer_id} is requesting file '{request.file_name}' (originally from {request.original_peer_id})")
        print("Do you want to share this file? (y/n): ", end="", flush=True)
        
        answer = input().lower().strip()
        can_share = answer == 'y'
        
        # Get our address for the response
        peer_addr = ""
        if can_share:
            # Use the local hostname and default port
            hostname = socket.gethostname()
            try:
                # Get the local IP address
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))  # Doesn't actually send anything
                local_ip = s.getsockname()[0]
                s.close()
                peer_addr = f"{local_ip}:12345"
            except:
                # Fall back to connection info
                if isinstance(addr, tuple) and len(addr) >= 1:
                    peer_addr = f"{addr[0]}:12345"
        
        # Send response
        response = OfflineFileResponse(
            request.file_name,
            peer_id,
            has_file=True,
            can_share=can_share,
            hash=file_hash,
            peer_address=peer_addr
        )
        
        send_offline_file_response(conn, response)
        print(f"Responded to offline file request: can share = {can_share}")
        
    except Exception as e:
        logger.error(f"Error handling offline file request: {e}")
        
        # Send error response
        try:
            error_response = OfflineFileResponse(
                "unknown",
                peer_id,
                has_file=False,
                can_share=False,
                error_message=str(e)
            )
            send_offline_file_response(conn, error_response)
        except:
            pass


def send_offline_file_response(conn, response):
    """
    Send an offline file response to the requester
    
    Args:
        conn: The connection socket
        response: The OfflineFileResponse object
    """
    try:
        response_json = response.to_json()
        conn.sendall(f"OFFLINE_FILE_RESPONSE:{response_json}".encode('utf-8'))
    except Exception as e:
        logger.error(f"Error sending offline file response: {e}")


def calculate_file_hash(file_path):
    """
    Calculate the SHA-256 hash of a file
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: Hexadecimal hash string
    """
    hasher = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Read and update hash in chunks of 4K
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    
    return hasher.hexdigest()