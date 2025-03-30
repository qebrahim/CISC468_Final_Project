import socket
import threading
import os
import random
import logging

logger = logging.getLogger(__name__)

# Keep track of all active connections
active_connections = set()
connection_callbacks = []


def register_connection_callback(callback):
    """Register a callback function to be called when a new connection is established"""
    if callback not in connection_callbacks:
        connection_callbacks.append(callback)


def notify_connection(addr, connected=True):
    """Notify all registered callbacks about connection status changes"""
    for callback in connection_callbacks:
        try:
            if connected:
                callback(addr)
            else:
                # Check if callback has a second parameter for disconnection
                if callable(getattr(callback, "_on_peer_disconnected", None)):
                    callback._on_peer_disconnected(addr)
        except Exception as e:
            logger.error(f"Error notifying connection callback: {e}")


def handle_request(conn, addr):
    try:
        # Add connection to active connections
        active_connections.add(conn)
        # Notify about new connection
        notify_connection(addr)

        while True:
            filename = conn.recv(1024).decode('utf-8')
            if not filename:
                break

            if os.path.exists(filename):
                conn.send(
                    b"EXISTS "+str(os.path.getsize(filename)).encode('utf-8'))
                with open(filename, 'rb') as f:
                    bytes_read = f.read(1024)
                    while bytes_read:
                        conn.send(bytes_read)
                        bytes_read = f.read(1024)
                logger.info(f"Sent: {filename}")
            else:
                conn.send(b"ERR")

    except Exception as e:
        logger.error(f"Error handling connection: {e}")
    finally:
        # Remove connection and notify about disconnection
        if conn in active_connections:
            active_connections.remove(conn)
        notify_connection(addr, connected=False)
        conn.close()


def request_file(host='localhost', port=12345, filename=''):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        full_path = os.path.join(os.getcwd(), filename)
        file_save_as = str(random.random()) + "_" + filename
        sock.sendall(full_path.encode('utf-8'))

        response = sock.recv(1024).decode('utf-8')
        if response.startswith("EXISTS"):
            filesize = int(response.split()[1])
            logger.info(f"File exists, size: {filesize} bytes")
            with open(os.path.join(os.getcwd(), file_save_as), 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    bytes_read = sock.recv(1024)
                    if not bytes_read:
                        break
                    f.write(bytes_read)
                    bytes_received += len(bytes_read)
            logger.info(f"Downloaded: {file_save_as}")
            return True
        else:
            logger.info("File does not exist.")
            return False

    except Exception as e:
        logger.error(f"Error requesting file: {e}")
        return False
    finally:
        sock.close()


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
