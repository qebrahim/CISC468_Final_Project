import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Global variables for state management
contact_manager = None
authentication = None


def init_authentication(peer_id, cm, auth):
    """Initialize the authentication module with dependencies"""
    global contact_manager, authentication
    contact_manager = cm
    authentication = auth
    logger.info(f"Authentication protocol initialized for peer {peer_id}")


def handle_auth_message(conn, addr, message):
    """Handle authentication protocol messages"""
    parts = message.split(':', 2)
    if len(parts) < 3:
        logger.error(f"Invalid auth message format: {message}")
        conn.sendall(b"ERR:INVALID_AUTH_MESSAGE")
        return

    auth_command = parts[1]
    payload = parts[2]

    if auth_command == "HELLO":
        handle_hello(conn, addr, payload)
    elif auth_command == "CHALLENGE":
        handle_challenge(conn, addr, payload)
    elif auth_command == "RESPONSE":
        handle_response(conn, addr, payload)
    elif auth_command == "VERIFY":
        handle_verify(conn, addr, payload)
    elif auth_command == "TRUST":
        handle_trust(conn, addr, payload)
    else:
        logger.error(f"Unknown auth command: {auth_command}")
        conn.sendall(b"ERR:UNKNOWN_AUTH_COMMAND")


def handle_hello(conn, addr, payload):
    """Handle the initial authentication handshake (HELLO)"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        pubkey = data.get("public_key")

        if not peer_id or not pubkey:
            logger.error("Missing peer_id or public_key in HELLO message")
            conn.sendall(b"ERR:INVALID_HELLO_MESSAGE")
            return

        # Store peer info temporarily (not yet trusted)
        logger.info(f"Received HELLO from peer {peer_id}")

        # Generate a challenge for the peer
        challenge_data = authentication.create_challenge(peer_id)

        # Send challenge
        response = {
            "peer_id": authentication.peer_id,
            "challenge_id": challenge_data["challenge_id"],
            "challenge": challenge_data["challenge_b64"]
        }

        conn.sendall(f"AUTH:CHALLENGE:{json.dumps(response)}".encode('utf-8'))
        logger.info(f"Sent challenge to peer {peer_id}")

    except Exception as e:
        logger.error(f"Error handling HELLO message: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")


def handle_challenge(conn, addr, payload):
    """Handle an authentication challenge from a peer"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        challenge_id = data.get("challenge_id")
        challenge = data.get("challenge")

        if not peer_id or not challenge_id or not challenge:
            logger.error("Missing data in CHALLENGE message")
            conn.sendall(b"ERR:INVALID_CHALLENGE_MESSAGE")
            return

        logger.info(f"Received CHALLENGE from peer {peer_id}")

        # Sign the challenge
        signature = authentication.sign_challenge(challenge)
        if not signature:
            logger.error("Failed to sign challenge")
            conn.sendall(b"ERR:SIGNATURE_FAILED")
            return

        # Send response with our signature and public key
        response = {
            "peer_id": authentication.peer_id,
            "challenge_id": challenge_id,
            "signature": signature,
            "public_key": authentication.get_public_key_pem()
        }

        conn.sendall(f"AUTH:RESPONSE:{json.dumps(response)}".encode('utf-8'))
        logger.info(f"Sent challenge response to peer {peer_id}")

    except Exception as e:
        logger.error(f"Error handling CHALLENGE message: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")


def handle_response(conn, addr, payload):
    """Handle a challenge response from a peer"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        challenge_id = data.get("challenge_id")
        signature = data.get("signature")
        pubkey = data.get("public_key")

        if not peer_id or not challenge_id or not signature or not pubkey:
            logger.error("Missing data in RESPONSE message")
            conn.sendall(b"ERR:INVALID_RESPONSE_MESSAGE")
            return

        logger.info(f"Received RESPONSE from peer {peer_id}")

        # Store the peer's public key temporarily for verification
        peer_addr = f"{addr[0]}:12345"  # Use standard port for storage
        temp_contact = {
            "peer_id": peer_id,
            "address": peer_addr,
            "public_key": pubkey
        }

        # Important: At this point, we need to ask the user for trust confirmation
        print(f"\nNew peer attempting to authenticate:")
        print(f"  Peer ID: {peer_id}")
        print(f"  Address: {peer_addr}")
        print()
        print(f"Do you want to verify and trust this peer? (y/n): ",
              end="", flush=True)

        # Send a VERIFY message to indicate we're in the verification process
        # This is just to acknowledge the response while we wait for user input
        verify_msg = {
            "peer_id": authentication.peer_id,
            "status": "verifying"
        }
        conn.sendall(f"AUTH:VERIFY:{json.dumps(verify_msg)}".encode('utf-8'))

        # The actual verification will happen when the user responds in the main loop
        # For now, we store the verification data for later use
        store_verification_request(
            peer_id, temp_contact, challenge_id, signature, conn)

    except Exception as e:
        logger.error(f"Error handling RESPONSE message: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")


def handle_verify(conn, addr, payload):
    """Handle verification status update"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        status = data.get("status")

        if not peer_id or not status:
            logger.error("Missing data in VERIFY message")
            conn.sendall(b"ERR:INVALID_VERIFY_MESSAGE")
            return

        logger.info(
            f"Received VERIFY from peer {peer_id} with status: {status}")

        if status == "verified":
            print(f"\nPeer {peer_id} has verified your identity!")

            # We don't automatically trust them back, that's a separate user decision
            # But we acknowledge their verification
            response = {
                "peer_id": authentication.peer_id,
                "status": "acknowledged"
            }
            conn.sendall(f"AUTH:VERIFY:{json.dumps(response)}".encode('utf-8'))

        elif status == "rejected":
            print(f"\nPeer {peer_id} has rejected the authentication request.")

        elif status == "verifying":
            # They're still deciding, nothing to do yet
            logger.info(
                f"Peer {peer_id} is considering our authentication request")

    except Exception as e:
        logger.error(f"Error handling VERIFY message: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")


def handle_trust(conn, addr, payload):
    """Handle trust status updates"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")

        # Handle both trust status and acknowledgment
        if "trusted" in data:
            trusted = data.get("trusted")

            if trusted:
                logger.info(f"Peer {peer_id} now trusts us")
                print(f"\nPeer {peer_id} has added you as a trusted contact!")
            else:
                logger.info(f"Peer {peer_id} no longer trusts us")
                print(
                    f"\nPeer {peer_id} has removed you as a trusted contact.")

            # Acknowledge the trust status update
            response = {
                "peer_id": authentication.peer_id,
                "status": "acknowledged"
            }
            conn.sendall(f"AUTH:TRUST:{json.dumps(response)}".encode('utf-8'))
        elif "status" in data:
            # This is an acknowledgment of our trust message
            status = data.get("status")
            logger.info(
                f"Received trust acknowledgment from peer {peer_id}: {status}")
        else:
            logger.error("Missing trusted or status in TRUST message")

    except Exception as e:
        logger.error(f"Error handling TRUST message: {e}")
        conn.sendall(b"ERR:INTERNAL_ERROR")

# Utility functions for authentication flow


# Global storage for pending verification requests
pending_verifications = {}


def store_verification_request(peer_id, contact_data, challenge_id, signature, conn):
    """Store a verification request for later processing by the user"""
    pending_verifications[peer_id] = {
        "contact_data": contact_data,
        "challenge_id": challenge_id,
        "signature": signature,
        "timestamp": time.time(),
        "conn": conn
    }
    logger.info(
        f"Stored verification request from peer {peer_id} for user confirmation")


def get_pending_verifications():
    """Get all pending verification requests"""
    # First clean up old requests (older than 5 minutes)
    current_time = time.time()
    expired_requests = []

    for peer_id, data in pending_verifications.items():
        if current_time - data["timestamp"] > 300:  # 5 minutes
            expired_requests.append(peer_id)

    for peer_id in expired_requests:
        del pending_verifications[peer_id]

    return pending_verifications


def process_verification_response(peer_id, trusted):
    """Process user's response to a verification request"""
    if peer_id not in pending_verifications:
        logger.error(f"No pending verification for peer {peer_id}")
        return False

    verification_data = pending_verifications[peer_id]
    challenge_id = verification_data["challenge_id"]
    signature = verification_data["signature"]
    contact_data = verification_data["contact_data"]
    conn = verification_data["conn"]

    try:
        if trusted:
            # Verify the signature
            valid = authentication.verify_signature(
                peer_id, challenge_id, signature)

            if valid:
                # Add to trusted contacts
                contact_manager.add_trusted_contact(
                    peer_id,
                    contact_data["address"],
                    contact_data["public_key"]
                )

                # Notify the peer that they are now trusted
                trust_msg = {
                    "peer_id": authentication.peer_id,
                    "trusted": True
                }

                try:
                    conn.sendall(
                        f"AUTH:TRUST:{json.dumps(trust_msg)}".encode('utf-8'))
                    logger.info(
                        f"Notified peer {peer_id} that they are now trusted")
                except:
                    logger.warning(
                        f"Could not notify peer {peer_id} - connection may be closed")

                # Also send verification confirmation
                verify_msg = {
                    "peer_id": authentication.peer_id,
                    "status": "verified"
                }

                try:
                    conn.sendall(
                        f"AUTH:VERIFY:{json.dumps(verify_msg)}".encode('utf-8'))
                except:
                    pass

                print(
                    f"Peer {peer_id} verified and added to trusted contacts!")

            else:
                # Invalid signature
                print(
                    f"Warning: Signature verification failed for peer {peer_id}!")

                # Notify the peer about rejection
                verify_msg = {
                    "peer_id": authentication.peer_id,
                    "status": "rejected"
                }

                try:
                    conn.sendall(
                        f"AUTH:VERIFY:{json.dumps(verify_msg)}".encode('utf-8'))
                except:
                    pass

            # Remove from pending verifications
            del pending_verifications[peer_id]
            return valid

        else:
            # User rejected the verification
            print(f"Rejected verification request from peer {peer_id}")

            # Notify the peer about rejection
            verify_msg = {
                "peer_id": authentication.peer_id,
                "status": "rejected"
            }

            try:
                conn.sendall(
                    f"AUTH:VERIFY:{json.dumps(verify_msg)}".encode('utf-8'))
            except:
                pass

            # Remove from pending verifications
            del pending_verifications[peer_id]
            return False

    except Exception as e:
        logger.error(f"Error processing verification response: {e}")
        return False

# Check if a peer is authenticated before allowing sensitive operations


def check_peer_authenticated(peer_address):
    """Check if a peer is authenticated before allowing file operations"""
    if not contact_manager:
        # If contact manager isn't initialized, allow operations (legacy mode)
        return True

    # Check if the peer is in our trusted contacts
    contact = contact_manager.get_contact_by_address(peer_address)
    if contact:
        logger.info(f"Peer {contact['peer_id']} is authenticated")
        return True

    logger.warning(f"Peer {peer_address} is not authenticated")
    return False


def initiate_authentication(peer_address):
    """Initiate the authentication process with a peer"""
    import socket

    try:
        # Parse address
        if ":" in peer_address:
            host, port_str = peer_address.split(":")
            port = int(port_str)
        else:
            host = peer_address
            port = 12345  # Default port

        logger.info(f"Initiating authentication with peer at {host}:{port}")

        # Create connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # Send HELLO message with our ID and public key
        hello_msg = {
            "peer_id": authentication.peer_id,
            "public_key": authentication.get_public_key_pem()
        }

        sock.sendall(f"AUTH:HELLO:{json.dumps(hello_msg)}".encode('utf-8'))
        logger.info(f"Sent HELLO to {host}:{port}")

        # Start thread to handle the rest of the authentication process
        import threading
        auth_thread = threading.Thread(
            target=handle_auth_responses,
            args=(sock, f"{host}:{port}")
        )
        auth_thread.daemon = True
        auth_thread.start()

        return True

    except Exception as e:
        logger.error(f"Error initiating authentication: {e}")
        print(f"Error connecting to peer: {e}")
        return False


def handle_auth_responses(sock, peer_address):
    """Handle responses during the authentication process"""
    try:
        while True:
            data = sock.recv(8192)
            if not data:
                logger.info(f"Connection closed by peer {peer_address}")
                break

            message = data.decode('utf-8')
            logger.debug(f"Received from {peer_address}: {message}")

            # Parse the message
            parts = message.split(':', 2)
            if len(parts) < 3 or parts[0] != "AUTH":
                logger.error(f"Invalid auth response: {message}")
                continue

            auth_command = parts[1]
            payload = parts[2]

            if auth_command == "CHALLENGE":
                handle_auth_challenge(sock, peer_address, payload)
            elif auth_command == "RESPONSE":
                handle_auth_response(sock, peer_address, payload)
            elif auth_command == "VERIFY":
                handle_auth_verify(sock, peer_address, payload)
            elif auth_command == "TRUST":
                handle_auth_trust(sock, peer_address, payload)
            else:
                logger.error(f"Unknown auth response command: {auth_command}")

    except Exception as e:
        logger.error(f"Error handling auth responses: {e}")
    finally:
        sock.close()


def handle_auth_challenge(sock, peer_address, payload):
    """Handle a challenge received during authentication"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        challenge_id = data.get("challenge_id")
        challenge = data.get("challenge")

        if not peer_id or not challenge_id or not challenge:
            logger.error("Missing data in CHALLENGE message")
            return

        logger.info(f"Received CHALLENGE from peer {peer_id}")

        # Sign the challenge
        signature = authentication.sign_challenge(challenge)
        if not signature:
            logger.error("Failed to sign challenge")
            return

        # Send response with our signature and public key
        response = {
            "peer_id": authentication.peer_id,
            "challenge_id": challenge_id,
            "signature": signature,
            "public_key": authentication.get_public_key_pem()
        }

        sock.sendall(f"AUTH:RESPONSE:{json.dumps(response)}".encode('utf-8'))
        logger.info(f"Sent challenge response to peer {peer_id}")

        # Store the peer's information for later verification
        # Extract host and port for address
        host, port = peer_address.split(":")
        standard_address = f"{host}:12345"  # Use standard port

        # Print information for user verification
        print(f"\nPending authentication with peer:")
        print(f"  Peer ID: {peer_id}")
        print(f"  Address: {standard_address}")
        print()
        print(f"Awaiting verification from peer...")

    except Exception as e:
        logger.error(f"Error handling challenge: {e}")


def handle_auth_response(sock, peer_address, payload):
    """Handle a response to our challenge"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        challenge_id = data.get("challenge_id")
        signature = data.get("signature")
        pubkey = data.get("public_key")

        if not peer_id or not challenge_id or not signature or not pubkey:
            logger.error("Missing data in RESPONSE message")
            return

        logger.info(f"Received RESPONSE from peer {peer_id}")

        # Split the address to get proper host
        host, port = peer_address.split(":")
        standard_address = f"{host}:12345"  # Use standard port

        # Important: At this point, we need to ask the user for trust confirmation
        print(f"\nPeer has responded to authentication challenge:")
        print(f"  Peer ID: {peer_id}")
        print(f"  Address: {standard_address}")
        print()
        print(f"Do you want to verify and trust this peer? (y/n): ",
              end="", flush=True)

        # Store the verification data for user decision in main loop
        temp_contact = {
            "peer_id": peer_id,
            "address": standard_address,
            "public_key": pubkey
        }

        # Send a VERIFY message to indicate we're in the verification process
        verify_msg = {
            "peer_id": authentication.peer_id,
            "status": "verifying"
        }
        sock.sendall(f"AUTH:VERIFY:{json.dumps(verify_msg)}".encode('utf-8'))

        # Store for later processing
        store_verification_request(
            peer_id, temp_contact, challenge_id, signature, sock)

    except Exception as e:
        logger.error(f"Error handling response: {e}")


def handle_auth_verify(sock, peer_address, payload):
    """Handle verification status update"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")
        status = data.get("status")

        if not peer_id or not status:
            logger.error("Missing data in VERIFY message")
            return

        logger.info(
            f"Received VERIFY from peer {peer_id} with status: {status}")

        if status == "verified":
            print(
                f"\nPeer {peer_id} has verified your identity and trusts you!")

            # Update our contact entry if it exists
            if contact_manager.is_trusted(peer_id):
                contact_manager.update_last_seen(peer_id)
                print(f"Updated trusted contact: {peer_id}")

        elif status == "rejected":
            print(f"\nPeer {peer_id} has rejected the authentication request.")

        elif status == "verifying":
            # They're still deciding, nothing to do yet
            logger.info(
                f"Peer {peer_id} is considering our authentication request")

    except Exception as e:
        logger.error(f"Error handling verify message: {e}")


def handle_auth_trust(sock, peer_address, payload):
    """Handle trust status updates"""
    try:
        # Parse the payload
        data = json.loads(payload)
        peer_id = data.get("peer_id")

        # Handle both trust status and acknowledgment
        if "trusted" in data:
            trusted = data.get("trusted")

            if trusted:
                logger.info(f"Peer {peer_id} now trusts us")
                print(f"\nPeer {peer_id} has added you as a trusted contact!")
            else:
                logger.info(f"Peer {peer_id} no longer trusts us")
                print(
                    f"\nPeer {peer_id} has removed you as a trusted contact.")

            # Acknowledge the trust status update
            response = {
                "peer_id": authentication.peer_id,
                "status": "acknowledged"
            }
            sock.sendall(f"AUTH:TRUST:{json.dumps(response)}".encode('utf-8'))
        elif "status" in data:
            # This is an acknowledgment of our trust message
            status = data.get("status")
            logger.info(
                f"Received trust acknowledgment from peer {peer_id}: {status}")
        else:
            logger.error(
                f"Missing trusted or status field in TRUST message from {peer_id}")

    except Exception as e:
        logger.error(f"Error handling trust message: {e}")
