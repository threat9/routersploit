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

        self.peer = "{}:{}".format(self.udp_target, self.udp_port)

        if is_ipv4(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif is_ipv6(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None

        self.udp_client.settimeout(UDP_SOCKET_TIMEOUT)

    def send(self, data):
        try:
            return self.udp_client.sendto(data, (self.udp_target, self.udp_port))
        except Exception as err:
            print_error(self.peer, "Error while sending data", err, verbose=self.verbosity)

        return None

    def recv(self, num):
        try:
            response = self.udp_client.recv(num)
            return response
        except Exception as err:
            print_error(self.peer, "Error while receiving data", err, verbose=self.verbosity)

        return None

    def close(self):
        try:
            self.udp_client.close()
        except Exception as err:
            print_error(self.peer, "Error while closing udp socket", err, verbose=self.verbosity)

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
