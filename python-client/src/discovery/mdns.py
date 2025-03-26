def discover_peers():
    import socket
    import struct
    import threading

    # mDNS multicast address and port
    MDNS_MULTICAST_ADDRESS = '224.0.0.251'
    MDNS_PORT = 5353

    def send_mdns_query():
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        # Construct the mDNS query
        query = b'\x00\x00'  # Transaction ID
        query += b'\x00\x00'  # Flags
        query += b'\x00\x01'  # Questions
        query += b'\x00\x00'  # Answers
        query += b'\x00\x00'  # Authority
        query += b'\x00\x00'  # Additional
        query += b'\x07example\x04local\x00'  # Query for example.local
        query += b'\x00\x01'  # Type A
        query += b'\x00\x01'  # Class IN

        # Send the query
        sock.sendto(query, (MDNS_MULTICAST_ADDRESS, MDNS_PORT))

    def listen_for_responses():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.bind(('', MDNS_PORT))

        while True:
            data, addr = sock.recvfrom(1024)
            print(f"Received response from {addr}: {data}")

    # Start the listener thread
    listener_thread = threading.Thread(target=listen_for_responses)
    listener_thread.start()

    # Send the mDNS query
    send_mdns_query()

# Call the discover_peers function to start the discovery process
discover_peers()