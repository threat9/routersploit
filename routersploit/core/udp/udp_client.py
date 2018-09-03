import socket

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import is_ipv4
from routersploit.core.exploit.utils import is_ipv6


UDP_SOCKET_TIMEOUT = 8.0


class UDPCli(object):
    def __init__(self, udp_target, udp_port, verbosity=False):
        self.udp_target = udp_target
        self.udp_port = udp_port
        self.verbosity = verbosity

        if is_ipv4(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif is_ipv6(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None

        self.udp_client.settimeout(UDP_SOCKET_TIMEOUT)

    def send(self, data):
        if type(data) is bytes:
            try:
                return self.udp_client.sendto(data, (self.udp_target, self.udp_port))
            except Exception:
                print_error("Exception while sending data", verbose=self.verbosity)
        else:
            print_error("Data to send is not type of bytes", verbose=self.verbosity)

        return None

    def recv(self, num):
        try:
            response = self.udp_client.recv(num)
            return response
        except socket.timeout:
            print_error("Socket did timeout", verbose=self.verbosity)
        except socket.error:
            print_error("Socket err", verbose=self.verbosity)

        return None

    def close(self):
        self.udp_client.close()
        return None


class UDPClient(Exploit):
    """ UDP Client exploit """

    target_protocol = Protocol.UDP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def udp_create(self, target=None, port=None):
        udp_target = target if target else self.target
        udp_port = port if port else self.port

        udp_client = UDPCli(udp_target, udp_port, verbosity=self.verbosity)
        return udp_client
