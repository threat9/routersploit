import socket

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.printer import print_status
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import is_ipv4
from routersploit.core.exploit.utils import is_ipv6


TCP_SOCKET_TIMEOUT = 8.0


class TCPClient(Exploit):
    """ TCP Client exploit """

    target_protocol = Protocol.TCP 

    def tcp_create(self):
        if is_ipv4(self.target):
            tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif is_ipv6(self.target):
            tcp_client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address")
            return None

        tcp_client.settimeout(TCP_SOCKET_TIMEOUT)
        return tcp_client

    def tcp_connect(self):
        try:
            tcp_client = self.tcp_create()
            tcp_client.connect((self.target, self.port))

            print_status("Connection established")
            return tcp_client

        except Exception:
            print_error("Could not connect")

        return None

    def tcp_send(self, tcp_client, data):
        if tcp_client:
            if type(data) is bytes:
                return tcp_client.send(data)
            elif type(data) is str:
                return tcp_client.send(bytes(data, "utf-8"))
            else:
                print_error("Data to send is not type of bytes or string")

        return None

    def tcp_recv(self, tcp_client, num):
        if tcp_client:
            try:
                response = tcp_client.recv(num)
                return str(response, "utf-8")
            except socket.timeout:
                print_error("Socket did timeout")

        return None

    def tcp_close(self, tcp_client):
        if tcp_client:
            tcp_client.close()
