import socket

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import is_ipv4
from routersploit.core.exploit.utils import is_ipv6


UDP_SOCKET_TIMEOUT = 8.0


class UDPCli(object):
    """ UDP Client provides methods to handle communication with UDP server """

    def __init__(self, udp_target: str, udp_port: int, verbosity: bool = False) -> None:
        """ UDP client constructor

        :param str udp_target: target UDP server ip address
        :param int udp_port: target UDP server port
        :param bool verbosity: display verbose output
        :return None:
        """

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

    def send(self, data: bytes) -> bool:
        """ Send UDP data

        :param bytes data: data that should be sent to the server
        :return bool: True if data was sent, False otherwise
        """

        try:
            self.udp_client.sendto(data, (self.udp_target, self.udp_port))
            return True
        except Exception as err:
            print_error(self.peer, "Error while sending data", err, verbose=self.verbosity)

        return False

    def recv(self, num: int) -> bytes:
        """ Receive UDP data

        :param int num: number of bytes that should received from the server
        :return bytes: bytes received from the server
        """

        try:
            response = self.udp_client.recv(num)
            return response
        except Exception as err:
            print_error(self.peer, "Error while receiving data", err, verbose=self.verbosity)

        return None

    def close(self) -> bool:
        """ Close UDP connection

        :return bool: True if connection was closed successful, False otherwise
        """

        try:
            self.udp_client.close()
            return True
        except Exception as err:
            print_error(self.peer, "Error while closing udp socket", err, verbose=self.verbosity)

        return False


class UDPClient(Exploit):
    """ UDP Client exploit """

    target_protocol = Protocol.UDP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def udp_create(self, target: str = None, port: int = None) -> UDPCli:
        """ Create UDP client

        :param str target: target UDP server ip address
        :param int port: target UDP server port
        :return UDPCli: UDP client object
        """

        udp_target = target if target else self.target
        udp_port = port if port else self.port

        udp_client = UDPCli(udp_target, udp_port, verbosity=self.verbosity)
        return udp_client
