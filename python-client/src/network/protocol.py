import socket
import threading
import os
import random

def handle_request(conn):
    while True:
        filename = conn.recv(1024).decode('utf-8')
        if not filename:
            break
        if os.path.exists(filename):
            conn.send(b"EXISTS "+str(os.path.getsize(filename)).encode('utf-8'))
            with open(filename,'rb') as f:
                bytes_read = f.read(1024)
                while bytes_read:
                    conn.send(bytes_read)
                    bytes_read = f.read(1024)
            print(f"Sent: {filename}")
        else:
            conn.send(b"ERR")
    
    conn.close()
def request_file(host='localhost',port=12345,filename=''):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host,port))
    full_path = os.getcwd()+ "\\"+filename
    file_save_as = str(random.random()) + "_"+filename
    sock.sendall(full_path.encode('utf-8'))

    response = sock.recv(1024).decode('utf-8')
    if response.startswith("EXISTS"):
        filesize = int(response.split()[1])
        print(f"File exists, size: {filesize} bytes")
        with open(f"{os.getcwd()}\\{file_save_as}",'wb') as f:
            bytes_recieved = 0
            while bytes_recieved < filesize:
                bytes_read = sock.recv(1024)
                if not bytes_read:
                    break
                f.write(bytes_read)
                bytes_recieved += len(bytes_read)
        print(f"Downloaded: {file_save_as}")

    else:
        print("File does not exist.")
    
    sock.close()     

def start_server(host='0.0.0.0',port=12345):
    def run_server(server_socket):
        while True:
                try:
                    conn, addr = server_socket.accept()
                    print(f"Connected by {addr}")
                    threading.Thread(target=handle_request, args=(conn,)).start()
                except Exception as e:
                    print(f"Server error: {e}")
                    break
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, port))
        sock.listen(5)
        print(f"Listening on {host}:{port}")
        
        # Start server in background thread
        server_thread = threading.Thread(target=run_server, args=(sock,))
        server_thread.daemon = True  # Allow clean program exit
        server_thread.start()
        
        return sock, server_thread  # Return for cleanup purposes
        
    except Exception as e:
        print(f"Failed to start server: {e}")
        raise
