import socket

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import is_ipv4
from routersploit.core.exploit.utils import is_ipv6


UDP_SOCKET_TIMEOUT = 8.0


class UDPClient(Exploit):
    """ UDP Client exploit """

    target_protocol = Protocol.UDP

    verbosity = OptBool("true", "Enable verbose output: true/false")

    def udp_create(self):
        if is_ipv4(self.target):
            udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif is_ipv6(self.target):
            udp_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None

        udp_client.settimeout(UDP_SOCKET_TIMEOUT)
        return udp_client

    def udp_send(self, udp_client, data):
        if udp_client:
            if type(data) is bytes:
                return udp_client.sendto(data, (self.target, self.port))
            elif type(data) is str:
                return udp_client.sendto(bytes(data, "utf-8"), (self.target, self.port))
            else:
                print_error("Data to send is not type of bytes or string", verbose=self.verbosity)

        return None

    def udp_recv(self, udp_client, num):
        if udp_client:
            try:
                response = udp_client.recv(num)
                return str(response, "utf-8")
            except socket.timeout:
                print_error("Socket did timeout", verbose=self.verbosity)
            except socket.error:
                print_error("Socket err", verbose=self.verbosity)

        return None

    def udp_close(self, udp_client):
        if udp_client:
            udp_client.close()

        return None
