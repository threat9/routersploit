import socket

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_status
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import is_ipv4
from routersploit.core.exploit.utils import is_ipv6


TCP_SOCKET_TIMEOUT = 8.0


class TCPClient(Exploit):
    """ TCP Client exploit """

    target_protocol = Protocol.TCP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def tcp_create(self):
        if is_ipv4(self.target):
            tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif is_ipv6(self.target):
            tcp_client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None

        tcp_client.settimeout(TCP_SOCKET_TIMEOUT)
        return tcp_client

    def tcp_connect(self):
        try:
            tcp_client = self.tcp_create()
            tcp_client.connect((self.target, self.port))

            print_status("Connection established", verbose=self.verbosity)
            return tcp_client

        except Exception as err:
            print_error("Could not connect", verbose=self.verbosity)
            print_error(err, verbose=self.verbosity)

        return None

    def tcp_send(self, tcp_client, data):
        if tcp_client:
            if type(data) is bytes:
                return tcp_client.send(data)
            else:
                print_error("Data to send is not type of bytes", verbose=self.verbosity)

        return None

    def tcp_recv(self, tcp_client, num):
        if tcp_client:
            try:
                response = tcp_client.recv(num)
                return response
            except socket.timeout:
                print_error("Socket did timeout", verbose=self.verbosity)
            except socket.error:
                print_error("Socket error", verbose=self.verbosity)

        return None

    def tcp_recv_all(self, tcp_client, num):
        if tcp_client:
            try:
                response = b""
                received = 0
                while received < num:
                    tmp = tcp_client.recv(num - received)

                    if tmp:
                        received += len(tmp)
                        response += tmp
                    else:
                        break

                return response
            except socket.timeout:
                print_error("Socket did timeout", verbose=self.verbosity)
            except socket.error:
                print_error("Socket error", verbose=self.verbosity)

        return None

    def tcp_close(self, tcp_client):
        if tcp_client:
            tcp_client.close()

        return None
