import telnetlib

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error


TELNET_TIMEOUT = 30.0


class TelnetCli(object):
    def __init__(self, telnet_target, telnet_port, verbosity=False):
        self.telnet_target = telnet_target
        self.telnet_port = telnet_port
        self.verbosity = verbosity

        self.telnet_client = None

    def connect(self):
        try:
            self.telnet_client = telnetlib.Telnet(self.telnet_target, self.telnet_port, timeout=TELNET_TIMEOUT)
            return self.telnet_client
        except Exception as err:
            print_error("Error while connecting", err, verbose=self.verbosity)

        return None

    def login(self, username, password, retries=1):
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
                    print_success("Telnet Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    return self.telnet_client
                else:
                    print_error("Telnet Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    break
            except EOFError:
                print_error("Telnet connection error", verbose=self.verbosity)
            except Exception as err:
                print_error(err, verbose=self.verbosity)

        return None

    def test_connect(self):
        try:
            self.telnet_client = telnetlib.Telnet(self.telnet_target, self.telnet_port, timeout=TELNET_TIMEOUT)
            self.telnet_client.expect([b"Login: ", b"login: ", b"Username: ", b"username: "], 5)
            self.telnet_client.close()

            return True
        except Exception as err:
            print_error("Telnet connection error", err, verbose=self.verbosity)

        return False

    def interactive(self):
        self.telnet_client.interact()

    def read_until(self, data):
        try:
            response = self.telnet_client.read_until(data, 5)
            return response
        except Exception:
            pass

        return None

    def write(self, data):
        try:
            return self.telnet_client.write(data, 5)
        except Exception as err:
            print_error("Error while writing", err, verbose=self.verbosity)

        return None

    def close(self):
        self.telnet_client.close()
        return None


class TelnetClient(Exploit):
    """ Telnet Client exploit """

    target_protocol = Protocol.TELNET

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def telnet_create(self, target=None, port=None):
        telnet_target = target if target else self.target
        telnet_port = port if port else self.port

        telnet_client = TelnetCli(telnet_target, telnet_port, verbosity=self.verbosity)
        return telnet_client
