import socket
import json
import hashlib
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class Peer:
    def __init__(self, peer_id, address):
        self.peer_id = peer_id
        self.address = address
        self.connected_peers = {}
        # Initialize shared directory - use ~/.p2p-share/shared as default
        self.shared_directory = Path.home() / '.p2p-share' / 'shared'
        self.shared_directory.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using shared directory: {self.shared_directory}")

    def connect(self, peer):
        if peer.peer_id not in self.connected_peers:
            self.connected_peers[peer.peer_id] = peer
            logger.info(f"Connected to peer: {peer.peer_id} at {peer.address}")

    def disconnect(self, peer):
        if peer.peer_id in self.connected_peers:
            del self.connected_peers[peer.peer_id]
            logger.info(f"Disconnected from peer: {peer.peer_id}")

    def send_file_request(self, peer_id, file_name):
        if peer_id in self.connected_peers:
            logger.info(f"Requesting file '{file_name}' from peer: {peer_id}")
            try:
                peer = self.connected_peers[peer_id]
                response = peer.receive_file_request(self.peer_id, file_name)

                if response and isinstance(response, dict):
                    if response['status'] == 'approved':
                        # Create socket connection to peer
                        host, port = peer.address.split(':')
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((host, int(port)))

                            # Send file request
                            request = f"REQUEST_FILE:{file_name}"
                            s.sendall(request.encode())

                            # Receive file data
                            file_path = self.shared_directory / file_name

                            # First read response header
                            data = s.recv(1024)
                            if data.startswith(b"FILE_DATA:"):
                                # Parse header to get file details
                                header = data.decode(
                                    'utf-8', errors='ignore').split(':', 3)
                                if len(header) < 3:
                                    logger.error(
                                        "Invalid file header received")
                                    return False

                                # Extract filename and filesize
                                received_filename = header[1]
                                try:
                                    filesize = int(header[2])
                                except ValueError:
                                    logger.error(
                                        f"Invalid file size in header: {header[2]}")
                                    return False

                                logger.info(
                                    f"Receiving file: {received_filename} ({filesize} bytes)")

                                # Write any data already received after the header
                                header_size = len(
                                    "FILE_DATA") + len(received_filename) + len(str(filesize)) + 3
                                with open(file_path, 'wb') as f:
                                    if len(data) > header_size:
                                        f.write(data[header_size:])
                                        bytes_received = len(
                                            data) - header_size
                                    else:
                                        bytes_received = 0

                                    # Continue receiving the file
                                    while bytes_received < filesize:
                                        chunk = s.recv(4096)
                                        if not chunk:
                                            break
                                        f.write(chunk)
                                        bytes_received += len(chunk)

                                # Verify file hash if provided
                                if 'file_hash' in response:
                                    if self._verify_file_hash(file_path, response['file_hash']):
                                        logger.info(
                                            f"File '{file_name}' successfully received and verified")
                                        return True
                                    else:
                                        logger.error(
                                            "File verification failed")
                                        file_path.unlink()  # Delete corrupted file
                                        return False
                                else:
                                    logger.info(
                                        f"File '{file_name}' successfully received (no hash verification)")
                                    return True
                            elif data.startswith(b"ERR"):
                                error_msg = data.decode('utf-8').split(':', 1)
                                if len(error_msg) > 1:
                                    logger.error(
                                        f"Error from peer: {error_msg[1]}")
                                else:
                                    logger.error("Unknown error occurred")
                                return False
                            else:
                                logger.error(
                                    f"Unexpected response: {data[:20]}")
                                return False
                    else:
                        logger.info("File request denied by peer")
                        return False
                else:
                    logger.error("Invalid response from peer")
                    return False

            except Exception as e:
                logger.error(f"Error requesting file: {e}")
                return False
        else:
            logger.error(f"Peer {peer_id} not connected")
            return False

    def receive_file_request(self, peer_id, file_name):
        logger.info(
            f"Received file request for '{file_name}' from peer: {peer_id}")
        try:
            file_path = self.shared_directory / file_name
            # Also check if file exists in the current directory as a fallback
            current_dir_path = Path(file_name)

            if file_path.exists():
                path_to_use = file_path
            elif current_dir_path.exists():
                path_to_use = current_dir_path
            else:
                logger.info(f"File '{file_name}' not found")
                return {'status': 'not_found'}

            # Calculate file hash
            file_hash = self._calculate_file_hash(path_to_use)

            # Request user consent
            print(
                f"\nAllow {peer_id} to download {file_name}? (y/n): ", end="")
            consent = input()
            if consent.lower() == 'y':
                return {
                    'status': 'approved',
                    'file_hash': file_hash,
                    'file_size': path_to_use.stat().st_size,
                    'file_path': str(path_to_use)
                }
            else:
                logger.info(f"Request for file '{file_name}' denied by user")
                return {'status': 'denied'}

        except Exception as e:
            logger.error(f"Error handling file request: {e}")
            return {'status': 'error', 'message': str(e)}

    def list_connected_peers(self):
        return list(self.connected_peers.keys())

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            hash_obj = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return None

    def _verify_file_hash(self, file_path, expected_hash):
        """Verify that file hash matches expected hash"""
        actual_hash = self._calculate_file_hash(file_path)
        if not actual_hash:
            return False
        return actual_hash == expected_hash
