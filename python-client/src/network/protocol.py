import socket
import threading
import os
import random
import logging
import os.path
from pathlib import Path

# Import the HashManager at the top of protocol.py
from crypto.hash_manager import HashManager
import json

# Initialize the HashManager (add to globals near the top of file)
hash_manager = None

logger = logging.getLogger(__name__)

# Keep track of all active connections and shared files
active_connections = set()
connection_callbacks = []
shared_files = []


def init_hash_manager(peer_id):
    global hash_manager
    hash_manager = HashManager(peer_id)


def register_connection_callback(callback):
    """Register a callback function to be called when a new connection is established"""
    if callback not in connection_callbacks:
        connection_callbacks.append(callback)


def notify_connection(addr, connected=True):
    """Notify all registered callbacks about connection status changes"""
    for callback in connection_callbacks:
        try:
            if connected:
                # Call callback for connection
                callback(addr)
            else:
                # Use proper method name for disconnection callback
                if hasattr(callback, "_on_peer_disconnected"):
                    callback._on_peer_disconnected(addr)
        except Exception as e:
            logger.error(f"Error notifying connection callback: {e}")


def add_shared_file(filepath):
    """Add a file to the list of shared files"""
    abs_path = os.path.abspath(filepath)
    if os.path.exists(abs_path) and abs_path not in shared_files:
        shared_files.append(abs_path)
        return True
    return False


def handle_request(conn, addr):
    try:
        # Add connection to active connections
        active_connections.add(conn)
        # Notify about new connection
        notify_connection(addr)

        while True:
            data = conn.recv(1024)
            if not data:
                break

            message = data.decode('utf-8')
            logger.info(f"Received from {addr}: {message}")

            # Parse the message (expected format: "REQUEST_FILE:filename")
            parts = message.split(':', 1)
            if len(parts) < 2:
                logger.error(f"Invalid request format: {message}")
                conn.sendall(b"ERR:INVALID_REQUEST")
                continue

            command = parts[0]

            if command == "REQUEST_FILE":
                filename = parts[1]
                handle_file_request(conn, addr, filename)
            elif command == "LIST_FILES":
                # Get list of shared files
                file_list = []

                # Add files from shared_files list
                for path in shared_files:
                    file_list.append(os.path.basename(path))

                # Check shared directory
                shared_dir = Path.home() / '.p2p-share' / 'shared'
                if shared_dir.exists():
                    for file_path in shared_dir.glob('*'):
                        if file_path.is_file() and file_path.name not in file_list:
                            file_list.append(file_path.name)

                # Send file list to client
                response = "FILE_LIST:" + ",".join(file_list)
                conn.sendall(response.encode('utf-8'))
                logger.info(f"Sent file list with {len(file_list)} files")
            else:
                logger.error(f"Unknown command: {command}")
                conn.sendall(b"ERR:UNKNOWN_COMMAND")

    except Exception as e:
        logger.error(f"Error handling connection: {e}")
    finally:
        # Remove connection and notify about disconnection
        if conn in active_connections:
            active_connections.remove(conn)
        notify_connection(addr, connected=False)
        conn.close()


# Modify the handle_file_request function to include hash information
def handle_file_request(conn, addr, filename):
    """Handle a file request from a client"""
    # First check if the requested file matches any shared file by basename
    found = False
    file_path = None

    # Check if the file exists as an exact path
    if os.path.exists(filename):
        found = True
        file_path = filename
    else:
        # Check if the file exists in shared files by basename
        basename = os.path.basename(filename)
        for path in shared_files:
            if os.path.basename(path) == basename:
                found = True
                file_path = path
                break

        # Also check in default shared directory
        if not found:
            shared_dir = Path.home() / '.p2p-share' / 'shared'
            potential_path = shared_dir / basename
            if potential_path.exists():
                found = True
                file_path = str(potential_path)

    if not found:
        logger.info(f"File not found: {filename}")
        conn.sendall(b"ERR:FILE_NOT_FOUND")
        return

    # Ask for user consent
    requester = f"{addr[0]}:{addr[1]}"
    print(f"\nAllow {requester} to download {filename}? (y/n): ",
          end="", flush=True)
    consent = input().lower().strip()

    if consent != 'y':
        logger.info(
            f"User denied request for file {filename} from {requester}")
        conn.sendall(b"ERR:REQUEST_DENIED")
        return

    try:
        # Get or compute the file hash
        hash_info = hash_manager.get_file_hash(filename)

        if not hash_info:
            # If we don't have hash info yet, calculate and store it
            file_hash = hash_manager.add_file_hash(filename, file_path)
        else:
            file_hash = hash_info['hash']

        # Open and read the file
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)

            # Send file header with hash information
            header = f"FILE_DATA:{os.path.basename(file_path)}:{file_size}:{file_hash}:"
            conn.sendall(header.encode('utf-8'))

            # Send file data in chunks
            chunk_size = 4096
            bytes_sent = 0

            while bytes_sent < file_size:
                chunk = file.read(chunk_size)
                if not chunk:
                    break

                conn.sendall(chunk)
                bytes_sent += len(chunk)

                # Log progress
                percent_complete = (bytes_sent / file_size) * 100
                if bytes_sent % (chunk_size * 10) == 0:  # Log every ~40KB
                    logger.info(f"Sending: {percent_complete:.1f}%")

            logger.info(f"File {filename} sent successfully")

    except Exception as e:
        error_msg = f"ERR:FILE_TRANSFER_FAILED:{str(e)}"
        logger.error(f"Error sending file: {e}")
        try:
            conn.sendall(error_msg.encode('utf-8'))
        except:
            pass

# Update the request_file function to handle hash verification


def request_file(host='localhost', port=12345, filename=''):
    """Request a file from a peer"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # Send the request using the expected format
        request_msg = f"REQUEST_FILE:{filename}"
        sock.sendall(request_msg.encode('utf-8'))

        # Receive initial response
        initial_response = sock.recv(4096)
        if not initial_response:
            logger.error("No response received")
            return False

        response = initial_response.decode('utf-8', errors='ignore')

        # Check for error response
        if response.startswith("ERR"):
            error_parts = response.split(':', 1)
            if len(error_parts) > 1:
                logger.error(f"Error from peer: {error_parts[1]}")
            else:
                logger.error("File not found or other error occurred")
            return False

        # Parse file header (expected format: "FILE_DATA:filename:filesize:filehash:")
        if not response.startswith("FILE_DATA:"):
            logger.error(f"Unexpected response: {response}")
            return False

        # Extract filename, filesize, and filehash
        header_parts = response.split(':', 4)  # Split up to 4 parts
        if len(header_parts) < 4:
            logger.error(f"Invalid file header: {response}")
            return False

        transfer_filename = header_parts[1]
        try:
            filesize = int(header_parts[2])
        except ValueError:
            logger.error(f"Invalid file size in header: {header_parts[2]}")
            return False

        # Extract hash if available
        file_hash = header_parts[3] if len(header_parts) >= 4 else None

        logger.info(f"Receiving file: {transfer_filename} ({filesize} bytes)")

        # Create a unique filename to avoid overwriting
        file_save_as = transfer_filename

        # Save to shared directory
        save_dir = Path.home() / '.p2p-share' / 'shared'
        save_dir.mkdir(parents=True, exist_ok=True)
        save_path = save_dir / file_save_as

        with open(save_path, 'wb') as f:
            # Write any data already received after the header
            # Adjust header size calculation to include the hash
            header_size = len(header_parts[0]) + len(header_parts[1]) + \
                len(header_parts[2]) + \
                len(header_parts[3]) + 4  # 4 for the colons

            if len(initial_response) > header_size:
                f.write(initial_response[header_size:])
                bytes_received = len(initial_response) - header_size
            else:
                bytes_received = 0

            # Continue receiving the file
            while bytes_received < filesize:
                chunk = sock.recv(4096)
                if not chunk:
                    break

                f.write(chunk)
                bytes_received += len(chunk)

                # Log progress
                percent_complete = (bytes_received / filesize) * 100
                if bytes_received % 40960 == 0:  # Log every ~40KB
                    logger.info(f"Receiving: {percent_complete:.1f}%")

        # Verify file integrity if we have a hash
        verified = False
        if file_hash:
            # Get existing hash info or create new entry
            existing_hash_info = hash_manager.get_file_hash(transfer_filename)

            if existing_hash_info:
                # If we already have this file in our database
                if existing_hash_info['hash'] != file_hash:
                    logger.warning(f"Received file has different hash than expected! "
                                   f"Expected: {existing_hash_info['hash']}, Got: {file_hash}")
                    # Verify the actual file
                    if not hash_manager.verify_file_hash(save_path, existing_hash_info['hash']):
                        logger.error(
                            f"File verification failed! The file may be corrupted or tampered with.")
                        # Optionally rename or quarantine the file
                        quarantine_path = save_dir / \
                            f"quarantine_{file_save_as}"
                        os.rename(save_path, quarantine_path)
                        logger.info(
                            f"Moved suspicious file to {quarantine_path}")
                        return False
                else:
                    # Hash matches what we expected
                    verified = hash_manager.verify_file_hash(
                        save_path, file_hash)
            else:
                # First time receiving this file, add to our hash database
                calculated_hash = hash_manager.add_file_hash(
                    transfer_filename, save_path, f"{host}:{port}")
                verified = (calculated_hash == file_hash)

        if verified:
            logger.info(f"File hash verified successfully!")
        elif file_hash:
            logger.warning(f"File hash verification failed!")
            return False
        else:
            logger.warning(f"No hash provided for verification")

        logger.info(f"Downloaded: {save_path}")
        return True

    except Exception as e:
        logger.error(f"Error requesting file: {e}")
        return False
    finally:
        sock.close()

# Update LIST_FILES handler to include file hash information


def handle_list_files_request(conn):
    """Handle request for list of shared files, including hash information"""
    try:
        # Get list of all files available for sharing
        file_list = []

        # Add files from shared_files list
        for path in shared_files:
            file_list.append(os.path.basename(path))

        # Check shared directory
        shared_dir = Path.home() / '.p2p-share' / 'shared'
        if shared_dir.exists():
            for file_path in shared_dir.glob('*'):
                if file_path.is_file() and file_path.name not in file_list:
                    file_list.append(file_path.name)

        # Get hash information for all files
        result = hash_manager.get_file_hashes_as_string(file_list)

        # Send file list with hash information
        response = f"FILE_LIST:{result}"
        conn.sendall(response.encode('utf-8'))
        logger.info(
            f"Sent file list with {len(file_list)} files and hash information")

    except Exception as e:
        logger.error(f"Error handling file list request: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")


def start_server(host='0.0.0.0', port=12345, connection_callback=None):
    """Start the server with an optional connection callback"""

    # Register the callback if provided
    if connection_callback:
        register_connection_callback(connection_callback)

    def run_server(server_socket):
        while True:
            try:
                conn, addr = server_socket.accept()
                logger.info(f"Connected by {addr}")
                client_thread = threading.Thread(
                    target=handle_request, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Server error: {e}")
                break

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        logger.info(f"Listening on {host}:{port}")

        # Start server in background thread
        server_thread = threading.Thread(target=run_server, args=(sock,))
        server_thread.daemon = True  # Allow clean program exit
        server_thread.start()

        return sock, server_thread  # Return for cleanup purposes

    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise
