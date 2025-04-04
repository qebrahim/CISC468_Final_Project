import socket
import threading
import os
import random
import logging
import os.path
from pathlib import Path
import time
import json
from network.offline_retrieval import handle_offline_file_request, request_file_from_alternative
from crypto.key_migration import handle_key_migration


logger = logging.getLogger(__name__)

# Keep track of all active connections and shared files
active_connections = set()
connection_callbacks = []
shared_files = []
hash_manager = None
contact_manager = None
authentication = None


def start_server(host='0.0.0.0', port=12345, connection_callback=None, peer_id=None):
    """Start the server with an optional connection callback and peer ID for hash manager"""

    # Initialize hash manager if peer_id is provided
    if peer_id:
        init_hash_manager(peer_id)

        # Initialize authentication system
        init_auth_system(peer_id)

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


# Function to check for and process pending verification requests
def process_pending_verifications():
    """Process any pending verification requests"""
    if not contact_manager or not authentication:
        return

    try:
        from crypto import auth_protocol
        pending = auth_protocol.get_pending_verifications()

        if pending:
            print("\nPending authentication requests:")
            for idx, (peer_id, data) in enumerate(pending.items(), 1):
                print(
                    f"{idx}. Peer {peer_id} - {data['contact_data']['address']}")

            print("\nEnter request number to process (or 0 to skip): ", end="")
            try:
                choice = int(input())
                if choice == 0:
                    return

                if 1 <= choice <= len(pending):
                    selected_peer_id = list(pending.keys())[choice - 1]

                    print(f"Verify peer {selected_peer_id}? (y/n): ", end="")
                    confirm = input().lower().strip()

                    auth_protocol.process_verification_response(
                        selected_peer_id, confirm == 'y')
            except ValueError:
                print("Invalid choice")
    except Exception as e:
        logger.error(f"Error processing pending verifications: {e}")


def handle_secure_file_receive(peer_id, message_type, payload):
    """Handle receiving a file through a secure channel"""
    try:
        from crypto.encryption import decrypt
        import base64
        import json

        # Get file receive state
        global secure_file_transfers
        if not hasattr(handle_secure_file_receive, 'secure_file_transfers'):
            handle_secure_file_receive.secure_file_transfers = {}

        secure_file_transfers = handle_secure_file_receive.secure_file_transfers

        if message_type == "FILE_HEADER":
            # Start a new file transfer
            try:
                header = json.loads(payload)
                filename = header.get("filename")
                filesize = header.get("size")
                filehash = header.get("hash", None)

                # Get encryption key if present
                transfer_key = None
                if "key" in header:
                    transfer_key = base64.b64decode(header["key"])

                if not filename or not filesize:
                    logger.error("Invalid file header")
                    return False

                # Prepare the output file
                save_dir = Path.home() / '.p2p-share' / 'shared'
                save_dir.mkdir(parents=True, exist_ok=True)
                save_path = save_dir / filename

                # Store transfer state
                secure_file_transfers[peer_id] = {
                    "filename": filename,
                    "path": str(save_path),
                    "size": filesize,
                    "hash": filehash,
                    "key": transfer_key,  # Store the encryption key
                    "received": 0,
                    "file": open(save_path, 'wb')
                }

                logger.info(f"Started secure file transfer for {filename}")
                print(f"\nReceiving encrypted file: {filename}")
                return True

            except Exception as e:
                logger.error(f"Error handling secure file header: {e}")
                return False

        elif message_type == "FILE_CHUNK":
            # Process a file chunk
            if peer_id not in secure_file_transfers:
                logger.error(f"No active file transfer for peer {peer_id}")
                return False

            transfer = secure_file_transfers[peer_id]

            try:
                # Decode the chunk
                encrypted_chunk = base64.b64decode(payload)

                # Decrypt if we have a key
                if transfer["key"]:
                    try:
                        chunk = decrypt(encrypted_chunk, transfer["key"])
                    except Exception as e:
                        logger.error(f"Error decrypting chunk: {e}")
                        # Fall back to writing encrypted data if decryption fails
                        chunk = encrypted_chunk
                else:
                    # No encryption - backward compatibility
                    chunk = encrypted_chunk

                # Write to file
                transfer["file"].write(chunk)
                transfer["received"] += len(chunk)

                # Log progress
                if transfer["received"] % 40960 == 0 or transfer["received"] >= transfer["size"]:
                    percent = (transfer["received"] / transfer["size"]) * 100
                    print(f"Receiving: {percent:.1f}%", end="\r")

                return True

            except Exception as e:
                logger.error(f"Error handling secure file chunk: {e}")
                return False

        elif message_type == "FILE_END":
            # Finish the file transfer
            if peer_id not in secure_file_transfers:
                logger.error(f"No active file transfer for peer {peer_id}")
                return False

            transfer = secure_file_transfers[peer_id]

            try:
                # Close the file
                transfer["file"].close()

                filename = transfer["filename"]
                filepath = transfer["path"]
                received = transfer["received"]
                expected = transfer["size"]
                filehash = transfer["hash"]

                # Check if we received all the data
                if received < expected:
                    logger.warning(
                        f"Incomplete file transfer: {received}/{expected} bytes")
                    print(
                        f"\nWarning: Received only {received} of {expected} bytes")
                else:
                    logger.info(f"File transfer complete: {filename}")
                    print(f"\nFile received successfully: {filename}")

                # Verify hash if available
                if hash_manager is not None and filehash:
                    if hash_manager.verify_file_hash(filepath, filehash):
                        logger.info("File hash verified successfully")
                        print("File integrity verified ✓")

                        # Store hash information
                        hash_manager.add_file_hash(filename, filepath, peer_id)
                    else:
                        logger.warning("File hash verification failed")
                        print(
                            "⚠️ Warning: File verification failed. The file may be corrupted.")

                # Clean up
                del secure_file_transfers[peer_id]

                # Add to shared files list
                if filepath not in shared_files:
                    shared_files.append(filepath)

                return True

            except Exception as e:
                logger.error(f"Error handling secure file end: {e}")
                return False

        else:
            logger.error(f"Unknown secure file message type: {message_type}")
            return False

    except Exception as e:
        logger.error(f"Error in secure file receive: {e}")
        return False

# Add handler for secure messages in the main protocol handler


def handle_secure_protocol(message, peer_id, conn):
    """Handle secure protocol messages after they've been decrypted"""
    try:
        # Parse the message type and payload
        parts = message.split(':', 1)
        if len(parts) < 2:
            logger.error(f"Invalid secure message format: {message}")
            return False

        message_type = parts[0]
        payload = parts[1] if len(parts) > 1 else ""

        # Handle different message types
        if message_type == "REQUEST_FILE":
            # Handle secure file request
            filename = payload
            handle_file_request(conn, None, filename,
                                secure=True, peer_id=peer_id)
            return True

        elif message_type == "FILE_HEADER" or message_type == "FILE_CHUNK" or message_type == "FILE_END":
            # Handle secure file transfer
            return handle_secure_file_receive(peer_id, message_type, payload)

        elif message_type == "FILE_LIST":
            # Handle file list response
            display_file_list(peer_id, payload)
            return True

        elif message_type == "ERROR":
            # Handle error message
            logger.error(f"Error from peer {peer_id}: {payload}")
            print(f"Error from peer: {payload}")
            return True

        else:
            logger.warning(f"Unknown secure message type: {message_type}")
            return False

    except Exception as e:
        logger.error(f"Error handling secure protocol message: {e}")
        return False


def display_file_list(peer_id_or_addr, file_list):
    """Display a list of files from a peer"""
    # Determine if we have peer_id or address
    peer_id = peer_id_or_addr

    if ":" in peer_id_or_addr:  # It's an address
        if contact_manager:
            contact = contact_manager.get_contact_by_address(peer_id_or_addr)
            if contact:
                peer_id = contact.get("peer_id", peer_id_or_addr)

    print(f"\nFiles available from peer {peer_id}:")

    if not file_list or file_list == "":
        print("  No files available")
        return

    # Check for the separator character to determine the format
    file_entries = []

    if ";" in file_list:
        # New format with multiple file entries separated by semicolons
        file_entries = file_list.split(";")
    elif "," in file_list:
        # Single file entry or old format
        # Check if it contains exactly two commas, which would indicate a file,hash,size triplet
        comma_count = file_list.count(",")
        if comma_count == 2:
            # This is likely a single file entry with hash and size
            file_entries = [file_list]
        else:
            # Old format (comma-separated filenames only)
            file_entries = file_list.split(",")
    else:
        # Single file with no metadata
        file_entries = [file_list]

    if not file_entries or (len(file_entries) == 1 and file_entries[0] == ""):
        print("  No files available")
        return

    for i, entry in enumerate(file_entries):
        if entry == "":
            continue

        # Check if entry contains file metadata
        if entry.count(",") == 2:
            # Parse file,hash,size triplet
            file_parts = entry.split(",")
            filename = file_parts[0]
            hash_value = file_parts[1]
            size_str = file_parts[2]

            # Format output
            size_display = ""
            if size_str:
                try:
                    size = int(size_str)
                    if size < 1024:
                        size_display = f" ({size} bytes)"
                    elif size < 1024 * 1024:
                        size_display = f" ({size / 1024:.1f} KB)"
                    else:
                        size_display = f" ({size / (1024 * 1024):.1f} MB)"
                except:
                    pass

            verified_str = " [verifiable]" if hash_value else ""

            print(f"  {i+1}. {filename}{size_display}{verified_str}")

            # Store hash information if hash manager is available
            if hash_manager and hash_value and filename:
                try:
                    size = int(size_str) if size_str else 0
                    hash_manager.Hashes[filename] = {
                        "hash": hash_value,
                        "size": size,
                        "origin_peer": peer_id,
                        "last_verified": time.time()
                    }
                except:
                    pass
        else:
            # Single filename without metadata
            print(f"  {i+1}. {entry}")

    # Save updated hashes if we're using hash manager
    if hash_manager:
        hash_manager.save_hashes()


def init_auth_system(peer_id):
    """Initialize the authentication system with dependencies"""
    global contact_manager, authentication

    try:
        from crypto.authentication import PeerAuthentication
        from crypto.contact_manager import ContactManager
        from crypto import auth_protocol

        # Initialize the contact manager
        contact_manager = ContactManager(peer_id)

        # Initialize the authentication system
        authentication = PeerAuthentication(peer_id, contact_manager)

        # Initialize the authentication protocol
        auth_protocol.init_authentication(
            peer_id, contact_manager, authentication)

        logger.info(f"Authentication system initialized for peer {peer_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize authentication system: {e}")
        logger.warning("Authentication will be disabled")
        return False


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
    if os.path.exists(abs_path) and abs_path not in shared_files:
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

            # Parse the message
            parts = message.split(':', 1)
            if len(parts) < 2:
                logger.error(f"Invalid request format: {message}")
                conn.sendall(b"ERR:INVALID_REQUEST")
                continue

            command = parts[0]

            # Check if this is an authentication message
            if command == "AUTH":
                # Handle it using the authentication protocol
                from crypto import auth_protocol
                auth_protocol.handle_auth_message(conn, addr, message)
                continue

            # Check if this is a secure channel message
            if command == "SECURE":
                # Handle it using the secure channel protocol
                try:
                    from crypto.secure_channel import handle_secure_message
                    result = handle_secure_message(conn, addr, message)

                    # Process the result if needed
                    if result and result.get("status") == "message_received":
                        # This is a decrypted application message
                        type = result.get("type")
                        payload = result.get("payload")
                        peer_id = result.get("peer_id")

                        # Log additional details for debugging
                        logger.info(
                            f"Received secure message: Type={type}, Peer={peer_id}")

                        # Handle the decrypted message based on type
                        if type == "REQUEST_FILE":
                            handle_file_request(
                                conn, addr, payload, secure=True, peer_id=peer_id)
                        elif type == "LIST_FILES":
                            handle_list_files_request(
                                conn, secure=True, peer_id=peer_id)
                        else:
                            logger.error(
                                f"Unknown secure message type: {type}")

                except Exception as e:
                    logger.error(f"Error handling secure message: {e}")
                    import traceback
                    traceback.print_exc()

                continue

            # For sensitive operations, check if peer is authenticated
            if command == "REQUEST_FILE" or command == "LIST_FILES":
                # Only check if auth system is active
                if contact_manager and authentication:
                    from crypto import auth_protocol
                    peer_addr = f"{addr[0]}:12345"  # Use standard port
                    if not auth_protocol.check_peer_authenticated(peer_addr):
                        # Peer not authenticated - send error or initiate authentication
                        logger.warning(
                            f"Unauthenticated access attempt from {addr}")
                        conn.sendall(b"ERR:AUTHENTICATION_REQUIRED")
                        continue

            # Handle regular commands
            if command == "REQUEST_FILE":
                filename = parts[1]
                handle_file_request(conn, addr, filename)
            elif command == "LIST_FILES":
                handle_list_files_request(conn)
            elif command == "ESTABLISH_SECURE":
                # Handle request to establish secure channel
                try:
                    peer_addr = f"{addr[0]}:12345"  # Use standard port
                    from crypto import auth_protocol
                    if not auth_protocol.check_peer_authenticated(peer_addr):
                        conn.sendall(b"ERR:AUTHENTICATION_REQUIRED")
                        continue

                    # Get the peer's ID
                    contact = auth_protocol.contact_manager.get_contact_by_address(
                        peer_addr)
                    if not contact:
                        conn.sendall(b"ERR:PEER_NOT_FOUND")
                        continue

                    peer_id = contact["peer_id"]

                    # Inform the user
                    print(
                        f"\nPeer {peer_id} requested to establish a secure encrypted channel.")
                    print("Do you want to accept? (y/n): ", end="", flush=True)

                    # For now, auto-accept in this implementation
                    # In a real implementation, you'd want to ask the user
                    print("y (auto-accepted)")

                    # Respond with acceptance
                    conn.sendall(b"ESTABLISH_SECURE:ACCEPTED")

                    logger.info(
                        f"Accepted secure channel request from {peer_id}")
                except Exception as e:
                    logger.error(f"Error handling secure channel request: {e}")
                    conn.sendall(b"ERR:INTERNAL_ERROR")
            elif command == "OFFLINE_FILE_REQUEST":
                # Handle offline file request
                if len(parts) > 1:
                    handle_offline_file_request(
                        conn,
                        addr,
                        parts[1],
                        authentication.peer_id if authentication else "unknown",
                        hash_manager
                    )
                else:
                    conn.sendall(b"ERR:INVALID_REQUEST")
            elif command == "MIGRATE_KEY":
                from crypto import auth_protocol
                if len(parts) > 1:
                    payload = parts[1]
                    # The message might be split due to size, try to get complete message
                    if not payload.endswith("}"):
                        # Keep reading until we get a complete JSON
                        while True:
                            try:
                                more_data = conn.recv(4096).decode('utf-8')
                                if not more_data:
                                    break
                                payload += more_data
                                if payload.endswith("}"):
                                    break
                            except Exception as e:
                                logger.error(
                                    f"Error reading full migration message: {e}")
                                break

                    # Now process the key migration with the complete message
                    handle_key_migration(payload, addr, conn,
                                         contact_manager=auth_protocol.contact_manager,
                                         authentication=auth_protocol.authentication)
                else:
                    conn.sendall(b"ERR:INVALID_KEY_MIGRATION")

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


def handle_file_request(conn, addr, filename, secure=False, peer_id=None):
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

        if secure:
            # Send error through secure channel
            from crypto.secure_channel import get_secure_channel
            channel = get_secure_channel(peer_id)
            if channel:
                # Modify to use file-specific error message
                channel.send_encrypted("ERROR", f"FILE_NOT_FOUND:{filename}")
        else:
            conn.sendall(b"ERR:FILE_NOT_FOUND")
        return

    # Additional logging for secure file requests
    logger.info(f"Processing {'secure' if secure else 'regular'} file request for {filename}")
    logger.info(f"Resolved file path: {file_path}")
    logger.info(f"Peer ID for request: {peer_id}")

    # Ask for user consent
    requester = f"{addr[0]}:{addr[1]}" if addr else peer_id

    # If authentication is active, show the trusted identity
    display_peer_id = "Unknown"
    if contact_manager:
        if peer_id:
            # We already have the peer ID from secure channel
            contact = contact_manager.get_trusted_contact(peer_id)
            if contact:
                display_peer_id = contact.get("nickname", peer_id)
        else:
            # Look up the peer address
            peer_addr = f"{addr[0]}:12345"  # Use standard port
            contact = contact_manager.get_contact_by_address(peer_addr)
            if contact:
                peer_id = contact["peer_id"]
                display_peer_id = contact.get("nickname", peer_id)

    if secure:
        print(f"\nSecure file request from {display_peer_id} for {filename}. Allow? (y/n): ",
              end="", flush=True)
    else:
        print(f"\nAllow {display_peer_id} at {requester} to download {filename}? (y/n): ",
              end="", flush=True)

    consent = input().lower().strip()

    if consent != 'y':
        logger.info(f"User denied request for file {filename} from {requester}")

        if secure:
            # Send error through secure channel
            from crypto.secure_channel import get_secure_channel
            channel = get_secure_channel(peer_id)
            if channel:
                channel.send_encrypted("ERROR", f"REQUEST_DENIED:{filename}")
        else:
            conn.sendall(b"ERR:REQUEST_DENIED")
        return

    try:
        # Get or compute the file hash, if hash manager is available
        file_hash = None
        if hash_manager is not None:
            try:
                hash_info = hash_manager.get_file_hash(filename)
                if hash_info:
                    file_hash = hash_info['hash']
                else:
                    # Calculate and store the hash
                    file_hash = hash_manager.add_file_hash(filename, file_path)
            except Exception as e:
                logger.warning(f"Error handling file hash: {e}")
                # Continue without hash if there's an error

        # Logging before sending file
        logger.info(f"Preparing to send file: {file_path}")
        logger.info(f"File hash: {file_hash or 'Not available'}")
        logger.info(f"Secure transfer: {secure}")
        logger.info(f"Peer ID for transfer: {peer_id}")

        # Check if we're using a secure channel
        if secure:
            # Send the file through the secure channel
            from crypto.secure_channel import get_secure_channel
            channel = get_secure_channel(peer_id)
            
            if channel:
                send_file_secure(peer_id, file_path, file_hash)
            else:
                logger.error(f"No secure channel found for peer {peer_id}")
                # Try to find an alternative channel
                from crypto.secure_channel import secure_channels
                logger.info(f"Available channels: {list(secure_channels.keys())}")
                
                # Check if there might be a channel with a different ID for the same peer
                for channel_id, sc in secure_channels.items():
                    if sc.socket == conn:
                        logger.info(f"Found channel with ID {channel_id} matching the connection")
                        send_file_secure(channel_id, file_path, file_hash)
                        return
                
                logger.error(f"Could not find any secure channel for this connection")
        else:
            # Send the file through regular connection
            send_file_regular(conn, file_path, file_hash)

    except Exception as e:
        error_msg = f"ERR:FILE_TRANSFER_FAILED:{str(e)}"
        logger.error(f"Error sending file: {e}")
        try:
            if secure:
                from crypto.secure_channel import get_secure_channel
                channel = get_secure_channel(peer_id)
                if channel:
                    channel.send_encrypted(
                        "ERROR", f"FILE_TRANSFER_FAILED:{str(e)}")
            else:
                conn.sendall(error_msg.encode('utf-8'))
        except:
            pass


def send_file_regular(conn, file_path, file_hash=None):
    """Send a file through a regular connection"""
    try:
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

            logger.info(
                f"File {os.path.basename(file_path)} sent successfully")

            # Update shared files list
            update_shared_files_list(file_path)

    except Exception as e:
        logger.error(f"Error sending file: {e}")
        raise


def send_file_secure(peer_id, file_path, file_hash=None):
    """Send a file securely with per-file encryption"""
    try:
        from crypto.secure_channel import get_secure_channel
        from crypto.encryption import encrypt, generate_key
        import base64
        import os

        # Get the secure channel
        channel = get_secure_channel(peer_id)
        if not channel:
            logger.error(f"No secure channel available for peer {peer_id}")
            return False

        # Generate a random key for this file transfer
        transfer_key = generate_key()

        # Open the file
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)
            basename = os.path.basename(file_path)

            # Send header with encryption key
            header = {
                "filename": basename,
                "size": file_size,
                "key": base64.b64encode(transfer_key).decode('utf-8')
            }

            if file_hash:
                header["hash"] = file_hash

            channel.send_encrypted("FILE_HEADER", json.dumps(header))

            # Send file in chunks
            chunk_size = 4096
            bytes_sent = 0

            while bytes_sent < file_size:
                chunk = file.read(chunk_size)
                if not chunk:
                    break

                # Encrypt the chunk
                encrypted_chunk = encrypt(chunk, transfer_key)

                # Encode as base64 for sending
                chunk_b64 = base64.b64encode(encrypted_chunk).decode('utf-8')

                # Send the encrypted chunk
                channel.send_encrypted("FILE_CHUNK", chunk_b64)

                bytes_sent += len(chunk)

                # Log progress
                percent_complete = (bytes_sent / file_size) * 100
                if bytes_sent % (chunk_size * 10) == 0:  # Log every ~40KB
                    logger.info(f"Sending (secure): {percent_complete:.1f}%")

            # Send end of file marker
            channel.send_encrypted("FILE_END", basename)

        logger.info(f"File {basename} sent securely")
        return True

    except Exception as e:
        logger.error(f"Error sending file securely: {e}")
        import traceback
        traceback.print_exc()
        return False


def update_shared_files_list(file_path):
    """Update the shared files list with a new file"""
    try:
        # Add file to shared files list if not already there
        basename = os.path.basename(file_path)
        shared_path = Path.home() / '.p2p-share' / 'shared' / basename

        # First ensure the file exists in our shared directory
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
        logger.warning(f"Error updating shared files: {e}")


def handle_list_files_request(conn, secure=False, peer_id=None):
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
        if hash_manager is not None:
            try:
                # New format with hash information, using semicolons between files
                hash_info = hash_manager.get_file_hashes_as_string(
                    file_list)

                if secure:
                    # Send through secure channel
                    from crypto.secure_channel import get_secure_channel
                    channel = get_secure_channel(peer_id)
                    if channel:
                        channel.send_encrypted("FILE_LIST", hash_info)
                        logger.info(
                            f"Sent secure file list with {len(file_list)} files")
                else:
                    # Send through regular connection
                    response = f"FILE_LIST:{hash_info}"
                    conn.sendall(response.encode('utf-8'))
                    logger.info(f"Sent file list with {len(file_list)} files")

            except Exception as e:
                # Fallback to old format if hash manager fails
                logger.warning(f"Error getting file hashes: {e}")

                if secure:
                    # Send through secure channel
                    from crypto.secure_channel import get_secure_channel
                    channel = get_secure_channel(peer_id)
                    if channel:
                        channel.send_encrypted(
                            "FILE_LIST", ','.join(file_list))
                else:
                    # Send through regular connection
                    response = f"FILE_LIST:{','.join(file_list)}"
                    conn.sendall(response.encode('utf-8'))
        else:
            # Old format without hashes
            if secure:
                # Send through secure channel
                from crypto.secure_channel import get_secure_channel
                channel = get_secure_channel(peer_id)
                if channel:
                    channel.send_encrypted("FILE_LIST", ','.join(file_list))
            else:
                # Send through regular connection
                response = f"FILE_LIST:{','.join(file_list)}"
                conn.sendall(response.encode('utf-8'))

            logger.info(f"Sent file list with {len(file_list)} files")

    except Exception as e:
        logger.error(f"Error handling file list request: {e}")

        if secure:
            from crypto.secure_channel import get_secure_channel
            channel = get_secure_channel(peer_id)
            if channel:
                channel.send_encrypted("ERROR", "INTERNAL_ERROR")
        else:
            conn.sendall(b"ERR:INTERNAL_ERROR")


def request_file(host, port, filename, use_secure=False):
    """Request a file from a remote peer"""
    try:
        # Check if we're using secure channel
        if use_secure:
            logger.info(
                f"Requesting file '{filename}' securely from {host}:{port}")

            # Look up peer ID from address for secure channel
            # Always use standard port for lookup
            peer_address = f"{host}:12345"
            if contact_manager is None:
                logger.error(
                    "Authentication system not initialized, secure transfer not available")
                return False

            contact = contact_manager.get_contact_by_address(peer_address)
            if not contact:
                logger.error(
                    f"Peer {peer_address} not authenticated, secure transfer not available")
                return False

            peer_id = contact["peer_id"]

            # Get or create secure channel
            from crypto.secure_channel import get_secure_channel, establish_secure_channel

            # Get existing channel or establish new one
            channel = get_secure_channel(peer_id)
            if not channel or not channel.established:
                # Try to establish a secure channel
                logger.info(f"Establishing secure channel with {peer_id}...")
                result = establish_secure_channel(peer_id, f"{host}:{port}")

                if result["status"] != "initiated":
                    logger.error("Failed to initiate secure channel")
                    return False

                # Wait a moment for channel to establish
                import time
                time.sleep(1)

                channel = get_secure_channel(peer_id)
                if not channel or not channel.established:
                    logger.error("Secure channel not established")
                    return False

            # Send the file request through secure channel
            return channel.send_encrypted("REQUEST_FILE", filename)

        else:
            # Use regular connection for non-secure requests
            logger.info(f"Requesting file '{filename}' from {host}:{port}")

            # Create a socket connection
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, int(port)))

            # Send file request
            request_msg = f"REQUEST_FILE:{filename}"
            sock.sendall(request_msg.encode('utf-8'))

            # Process the response in a separate thread to avoid blocking
            def receive_file():
                try:
                    # Create buffer reader
                    import io
                    reader = sock.makefile('rb')

                    # Read initial response
                    header = reader.readline().decode('utf-8').strip()

                    if header.startswith("ERR"):
                        logger.error(f"Error from peer: {header}")
                        print(f"Error from peer: {header}")
                        sock.close()
                        return

                    # Parse file header (expected format: "FILE_DATA:filename:filesize:filehash:")
                    if not header.startswith("FILE_DATA:"):
                        logger.error(f"Unexpected response: {header}")
                        print(f"Unexpected response: {header}")
                        sock.close()
                        return

                    # Parse header parts
                    parts = header.split(":")
                    if len(parts) < 3:
                        logger.error(f"Invalid file header: {header}")
                        sock.close()
                        return

                    filename = parts[1]
                    try:
                        filesize = int(parts[2])
                    except ValueError:
                        logger.error(f"Invalid file size: {parts[2]}")
                        sock.close()
                        return

                    # Extract hash if present
                    filehash = None
                    if len(parts) > 3:
                        filehash = parts[3]

                    print(f"Receiving file: {filename} ({filesize} bytes)")

                    # Create directory for downloads if it doesn't exist
                    save_dir = Path.home() / '.p2p-share' / 'shared'
                    save_dir.mkdir(parents=True, exist_ok=True)

                    save_path = save_dir / filename
                    with open(save_path, 'wb') as f:
                        bytes_received = 0
                        buffer_size = 4096

                        while bytes_received < filesize:
                            chunk = sock.recv(
                                min(buffer_size, filesize - bytes_received))
                            if not chunk:
                                break

                            f.write(chunk)
                            bytes_received += len(chunk)

                            # Display progress
                            percent = (bytes_received / filesize) * 100
                            if bytes_received % (buffer_size * 10) == 0 or bytes_received == filesize:
                                print(f"Receiving: {percent:.1f}%", end="\r")

                        print()  # New line after progress

                    # Verify file hash if available
                    if hash_manager is not None and filehash:
                        print("Verifying file integrity...")
                        if hash_manager.verify_file_hash(save_path, filehash):
                            print("✅ File integrity verified successfully")

                            # Store hash information
                            hash_manager.add_file_hash(
                                filename, save_path, f"{host}:{port}")
                        else:
                            print("⚠️ File verification failed!")

                            # Ask if user wants to keep the file
                            print("Keep potentially corrupted file? (y/n): ", end="")
                            keep_file = input().lower()
                            if keep_file != 'y':
                                os.remove(save_path)
                                print("File deleted")
                                sock.close()
                                return

                    print(f"File downloaded successfully to {save_path}")

                    # Add to shared files list if not already there
                    if str(save_path) not in shared_files:
                        shared_files.append(str(save_path))

                except Exception as e:
                    logger.error(f"Error receiving file: {e}")
                    print(f"Error receiving file: {e}")
                finally:
                    sock.close()

            # Start file reception in background thread
            import threading
            file_thread = threading.Thread(target=receive_file)
            file_thread.daemon = True
            file_thread.start()

            return True
    except ConnectionRefusedError:
        print(f"Could not connect to peer {host}:{port}")
        print("Attempting to find alternative sources...")

        # Try to get hash information if available
        file_hash = None
        if hash_manager is not None:
            hash_info = hash_manager.get_file_hash(filename)
            if hash_info:
                file_hash = hash_info.get('hash')
                print(f"Using hash {file_hash} for verification")

        # Get our peer ID from authentication system
        requester_id = authentication.peer_id if authentication else "unknown"

        # Try to find the file from alternative peers
        from crypto import auth_protocol
        success, alternative_peer, error_msg = request_file_from_alternative(
            filename,
            "unknown",  # We don't know the original peer ID if connection failed
            requester_id,
            file_hash,
            auth_protocol.contact_manager
        )

        if success:
            print(
                f"Successfully retrieved file from alternative peer: {alternative_peer}")
            return True
        else:
            print(f"Failed to find alternative source for file: {error_msg}")
            return False
    except Exception as e:
        logger.error(f"Error requesting file: {e}")
        print(f"Error requesting file: {e}")
        return False
