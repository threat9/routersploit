import telnetlib

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error


TELNET_TIMEOUT = 30.0


class TelnetCli(object):
    """ Telnet Client provides methods to handle communication with Telnet server """

    def __init__(self, telnet_target: str, telnet_port: int, verbosity: bool = False) -> None:
        """ Telnet client constructor

        :param str telnet_target: target Telnet server ip address
        :param int telnet_port: target Telnet server port
        :param bool verbosity: display verbose output
        :return None:
        """

        self.telnet_target = telnet_target
        self.telnet_port = telnet_port
        self.verbosity = verbosity

        self.peer = "{}:{}".format(self.telnet_target, self.telnet_port)

        self.telnet_client = None

    def connect(self) -> bool:
        """ Connect to Telnet server

        :return bool: True if connection was successful, False otherwise
        """

        try:
            self.telnet_client = telnetlib.Telnet(self.telnet_target, self.telnet_port, timeout=TELNET_TIMEOUT)
            return True
        except Exception as err:
            print_error(self.peer, "Telnet Error while connecting to the server", err, verbose=self.verbosity)

        return False

    def login(self, username: str, password: str, retries: int = 1) -> bool:
        """ Login to Telnet server

        :param str username: Telnet account username
        :param str password: Telnet account password
        :param int retries: number of authentication retries
        :return bool: True if login was successful, False otherwise
        """

        for _ in range(retries):
            try:
                if not self.connect():
                    continue

                self.telnet_client.expect([b"Login: ", b"login: ", b"Username: ", b"username: "], 5)
                self.telnet_client.write(bytes(username, "utf-8") + b"\r\n")
                self.telnet_client.expect([b"Password: ", b"password: "], 5)
                self.telnet_client.write(bytes(password, "utf-8") + b"\r\n")
                self.telnet_client.write(b"\r\n")

                (i, obj, res) = self.telnet_client.expect([b"Incorrect", b"incorrect"], 5)

                if i == -1 and any([x in res for x in [b"#", b"$", b">"]]) or len(res) > 500:  # big banner e.g. mikrotik
                    print_success(self.peer, "Telnet Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    return True
                else:
                    print_error(self.peer, "Telnet Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    break
            except Exception as err:
                print_error(self.peer, "Telnet Error while authenticating to the server", err, verbose=self.verbosity)

        return False

    def test_connect(self) -> bool:
        """ Test connection to Telnet server

        :return bool: True if test connection was successful, False otherwise
        """

        try:
            self.telnet_client = telnetlib.Telnet(self.telnet_target, self.telnet_port, timeout=TELNET_TIMEOUT)
            self.telnet_client.expect([b"Login: ", b"login: ", b"Username: ", b"username: "], 5)
            self.telnet_client.close()

            return True
        except Exception as err:
            print_error(self.peer, "Telnet Error while testing connection to the server", err, verbose=self.verbosity)

        return False

    def interactive(self) -> None:
        """ Start interactive mode with Telnet server

        :return None:
        """

        self.telnet_client.interact()

    def read_until(self, data: bytes) -> bytes:
        """ Read until specified data found in response

        :param bytes data: bytes until which data should be read
        :return bytes: bytes read until data
        """

        try:
            response = self.telnet_client.read_until(data, 5)
            return response
        except Exception as err:
            print_error(self.peer, "Telnet Error while reading data from the server", err, verbose=self.verbosity)

        return None

    def write(self, data: bytes) -> bool:
        """ Write data to Telnet server

        :param bytes data: data that should be written to Telnet server
        :return bool: True if data was written successfuly, False otherwise
        """

        try:
            self.telnet_client.write(data, 5)
            return True
        except Exception as err:
            print_error(self.peer, "Telnet Error while writing to the server", err, verbose=self.verbosity)

        return False

    def close(self) -> bool:
        """ Close connection to Telnet server

        :return bool: True if closing connection was successful, False otherwise
        """

        try:
            self.telnet_client.close()
            return True
        except Exception as err:
            print_error(self.peer, "Telnet Error while closing connection", err, verbose=self.verbosity)

        return False


class TelnetClient(Exploit):
    """ Telnet Client exploit """

    target_protocol = Protocol.TELNET

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def telnet_create(self, target: str = None, port: int = None) -> TelnetCli:
        """ Create Telnet client

        :param str target: target Telnet ip address
        :param int port: target Telnet port
        :return TelnetCli: Telnet client object
        """

        telnet_target = target if target else self.target
        telnet_port = port if port else self.port

        telnet_client = TelnetCli(telnet_target, telnet_port, verbosity=self.verbosity)
        return telnet_client
