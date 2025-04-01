import shutil
import socket
import threading
import os
import random
import logging
import os.path
from pathlib import Path
import time

logger = logging.getLogger(__name__)

# Keep track of all active connections and shared files
active_connections = set()
connection_callbacks = []
shared_files = []
hash_manager = None


def init_hash_manager(peer_id):
    """Initialize the hash manager with the given peer ID"""
    global hash_manager
    try:
        from crypto.hash_manager import HashManager
        hash_manager = HashManager(peer_id)
        logger.info(f"Hash manager initialized for peer {peer_id}")
    except Exception as e:
        logger.warning(f"Failed to initialize hash manager: {e}")
        logger.warning("File verification will be disabled")


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
    if os.path.exists(abs_path):
        if abs_path not in shared_files:
            shared_files.append(abs_path)

            # Add file hash if hash manager is available
            if hash_manager is not None:
                try:
                    basename = os.path.basename(abs_path)
                    file_hash = hash_manager.add_file_hash(basename, abs_path)
                    logger.info(
                        f"Added file hash for {basename}: {file_hash[:8]}...")
                except Exception as e:
                    logger.warning(f"Failed to add file hash: {e}")

            # Ensure file is copied to shared directory
            try:
                shared_dir = Path.home() / '.p2p-share' / 'shared'
                shared_dir.mkdir(parents=True, exist_ok=True)
                target_path = shared_dir / os.path.basename(abs_path)

                # Copy file if it's not already in the shared directory
                if not target_path.exists():
                    shutil.copy2(abs_path, target_path)
                    logger.info(
                        f"Copied {os.path.basename(abs_path)} to shared directory")
            except Exception as e:
                logger.error(f"Error copying file to shared directory: {e}")

            return True
        return False
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
                handle_list_files_request(conn)
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
        # Get or compute the file hash, if hash manager is available
        file_hash = None
        if hash_manager is not None:
            try:
                hash_info = hash_manager.get_file_hash(basename)
                if hash_info:
                    file_hash = hash_info['hash']
                else:
                    # Calculate and store the hash
                    file_hash = hash_manager.add_file_hash(basename, file_path)
            except Exception as e:
                logger.warning(f"Error handling file hash: {e}")
                # Continue without hash if there's an error

        # Open and read the file
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)

            # Send file header with hash information if available
            if file_hash:
                header = f"FILE_DATA:{os.path.basename(file_path)}:{file_size}:{file_hash}:"
            else:
                header = f"FILE_DATA:{os.path.basename(file_path)}:{file_size}:"

            conn.sendall(header.encode('utf-8'))

            # Small delay to ensure header is processed separately
            time.sleep(0.05)

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

            # Add file to shared files list if not already there
            basename = os.path.basename(file_path)
            shared_path = Path.home() / '.p2p-share' / 'shared' / basename

            # First ensure the file exists in our shared directory
            try:
                if not shared_path.exists():
                    # Copy file to shared directory if it's not already there
                    shared_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, 'rb') as src, open(shared_path, 'wb') as dst:
                        dst.write(src.read())
                    logger.info(f"Copied {basename} to shared directory")

                # Add to shared files list if not already present
                str_path = str(shared_path)
                if str_path not in shared_files:
                    shared_files.append(str_path)
                    logger.info(f"Added {basename} to shared files list")
            except Exception as e:
                logger.warning(f"Error adding file to shared directory: {e}")

    except Exception as e:
        error_msg = f"ERR:FILE_TRANSFER_FAILED:{str(e)}"
        logger.error(f"Error sending file: {e}")
        try:
            conn.sendall(error_msg.encode('utf-8'))
        except:
            pass


def handle_list_files_request(conn):
    """Handle request for list of shared files, including hash information"""
    try:
        # Get list of all files available for sharing
        file_list = []

        # Add files from shared_files list
        for path in shared_files:
            basename = os.path.basename(path)
            if basename not in file_list:
                file_list.append(basename)

        # Check shared directory
        shared_dir = Path.home() / '.p2p-share' / 'shared'
        if shared_dir.exists():
            for file_path in shared_dir.glob('*'):
                if file_path.is_file() and file_path.name not in file_list:
                    file_list.append(file_path.name)

        logger.info(f"Found {len(file_list)} files to share")

        # Construct the response
        response = "FILE_LIST:"

        # Add file content only if there are files
        if file_list:
            if hash_manager is not None:
                try:
                    # New format with hash information, using semicolons between files
                    hash_info = hash_manager.get_file_hashes_as_string(
                        file_list)
                    response += hash_info
                    logger.debug(f"Using new format with hash information")
                except Exception as e:
                    # Fallback to old format if hash manager fails
                    logger.warning(f"Error getting file hashes: {e}")
                    response += ','.join(file_list)
                    logger.debug(f"Falling back to old format without hashes")
            else:
                # Old format without hashes
                response += ','.join(file_list)
                logger.debug(f"Using old format (no hash manager)")

        # Use repr to show all characters including whitespace
        logger.info(
            f"Sending file list response (length: {len(response)}): {repr(response)}")

        # Send the response
        conn.sendall(response.encode('utf-8'))

        # Small delay to ensure the data is sent completely
        time.sleep(0.1)

        logger.info(f"Sent file list with {len(file_list)} files")

    except Exception as e:
        logger.error(f"Error handling file list request: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")


def request_file(host='localhost', port=12345, filename=''):
    """Request a file from a peer"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info(f"Connecting to {host}:{port} to request file {filename}")
        sock.connect((host, port))

        # Send the request using the expected format
        request_msg = f"REQUEST_FILE:{filename}"
        sock.sendall(request_msg.encode('utf-8'))
        logger.info(f"Sent request: {request_msg}")

        # Receive initial response
        initial_response = sock.recv(4096)
        if not initial_response:
            logger.error("No response received")
            return False

        response = initial_response.decode('utf-8', errors='ignore')
        logger.info(f"Received initial response: {response[:100]}...")

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

        # Extract filename, filesize, and filehash (if provided)
        header_parts = response.split(':', 4)
        if len(header_parts) < 3:
            logger.error(f"Invalid file header: {response}")
            return False

        transfer_filename = header_parts[1]
        try:
            filesize = int(header_parts[2])
        except ValueError:
            logger.error(f"Invalid file size in header: {header_parts[2]}")
            return False

        # Extract hash if available
        file_hash = None
        if len(header_parts) >= 4 and header_parts[3]:
            file_hash = header_parts[3]
            logger.info(f"Received file hash: {file_hash[:8]}...")

        logger.info(f"Receiving file: {transfer_filename} ({filesize} bytes)")

        # Create a unique filename to avoid overwriting
        file_save_as = transfer_filename

        # Save to shared directory
        save_dir = Path.home() / '.p2p-share' / 'shared'
        save_dir.mkdir(parents=True, exist_ok=True)
        save_path = save_dir / file_save_as

        # Calculate header size based on number of fields
        # Header is everything up to and including the last colon
        header_end_pos = response.rfind(':')
        if header_end_pos == -1:
            logger.error("Could not find end of header")
            return False

        with open(save_path, 'wb') as f:
            # Write any data already received after the header
            if len(initial_response) > header_end_pos + 1:
                f.write(initial_response[header_end_pos + 1:])
                bytes_received = len(initial_response) - (header_end_pos + 1)
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

        # Verify file hash if available and we have a hash manager
        if hash_manager is not None and file_hash:
            try:
                if hash_manager.verify_file_hash(save_path, file_hash):
                    logger.info("File hash verified successfully")

                    # Store the hash information for future verification
                    hash_manager.add_file_hash(
                        transfer_filename, save_path, f"{host}:{port}")
                else:
                    logger.warning(
                        "File hash verification failed - file may be corrupted")
                    print(
                        "⚠️ Warning: File hash verification failed. The file may be corrupted.")
                    # Option to remove corrupt file could be added here
            except Exception as e:
                logger.error(f"Error during hash verification: {e}")

        logger.info(f"Downloaded: {save_path}")
        return True

    except Exception as e:
        logger.error(f"Error requesting file: {e}")
        return False
    finally:
        sock.close()


def start_server(host='0.0.0.0', port=12345, connection_callback=None, peer_id=None):
    """Start the server with an optional connection callback and peer ID for hash manager"""

    # Initialize hash manager if peer_id is provided
    if peer_id:
        init_hash_manager(peer_id)

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
