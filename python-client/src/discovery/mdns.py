from zeroconf import ServiceInfo, Zeroconf
import socket
import json
import time
import traceback


class PeerDiscovery:
    def __init__(self, peer_id, port):
        self.zeroconf = Zeroconf()
        self.peer_id = peer_id
        self.port = port
        self.service_name = f"p2p-share-{peer_id}._p2p-share._tcp.local."
    
 

        
    def start_advertising(self):
        try:
            ip_addr = socket.gethostbyname(socket.gethostname())
            print(f"Local IP address: {ip_addr}")

            info = ServiceInfo(
                "_p2p-share._tcp.local.",
                self.service_name,
                addresses=[socket.inet_aton(ip_addr)],
                port=self.port,
                properties={"peer_id": self.peer_id},
                server=f"{socket.gethostname()}.local.",
            )

            print(f"Advertising service: {self.service_name} at {ip_addr}:{self.port}")
            self.zeroconf.register_service(info)

        except Exception as e:
            print("ServiceInfo creation failed:")
            traceback.print_exc()
            
            print(f"Advertising service: {self.service_name} at {ip_addr}:{self.port}")
            self.zeroconf.register_service(info)
        
    def stop_advertising(self):
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()