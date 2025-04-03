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

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip

    def start_advertising(self):
        try:
            ip_addr = self.get_local_ip()
            print(
                f" Advertising service {self.service_name} at {ip_addr}:{self.port}")

            info = ServiceInfo(
                "_p2p-share._tcp.local.",
                self.service_name,
                addresses=[socket.inet_aton(ip_addr)],
                port=self.port,
                properties={"peer_id": self.peer_id},
                server=f"{socket.gethostname()}.local.",
            )

            self.zeroconf.register_service(info)
        except Exception as e:
            print("❌ Service advertisement failed:")
            traceback.print_exc()

    def stop_advertising(self):
        print(f"🔴 Stopping service {self.service_name}")
        self.zeroconf.unregister_service(self.service_name)
        self.zeroconf.close()
