import telnetlib

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error


TELNET_TIMEOUT = 30.0


class TelnetClient(Exploit):
    """ Telnet Client exploit """

    target_protocol = Protocol.TELNET

    verbosity = OptBool("true", "Enable verbose output: true/false")

    def telnet_connect(self, target=None, port=None):
        if not target:
            target = self.target
        if not port:
            port = self.port

        try:
            telnet_client = telnetlib.Telnet(target, port, timeout=TELNET_TIMEOUT)
            return telnet_client
        except Exception:
            pass

        return None

    def telnet_login(self, username, password, target=None, port=None, retries=1):
        if not target:
            target = self.target
        if not port:
            port = self.port

        for _ in range(retries):
            try:
                telnet_client = self.telnet_connect(target=target, port=port)
                if not telnet_client:
                    continue

                telnet_client.expect([b"Login: ", b"login: ", b"Username: ", b"username: "], 5)
                telnet_client.write(bytes(username, "utf-8") + b"\r\n")
                telnet_client.expect([b"Password: ", b"password: "], 5)
                telnet_client.write(bytes(password, "utf-8") + b"\r\n")
                telnet_client.write(b"\r\n")

                (i, obj, res) = telnet_client.expect([b"Incorrect", b"incorrect"], 5)

                if i == -1 and any([x in res for x in [b"#", b"$", b">"]]) or len(res) > 500:  # big banner e.g. mikrotik
                    print_success("Telnet Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    return telnet_client
                else:
                    print_error("Telnet Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    break
            except EOFError:
                print_error("Telnet connection error", verbose=self.verbosity)
            except Exception as err:
                print_error(err, verbose=self.verbosity)

        return None

    def telnet_test_connect(self):
        try:
            telnet_client = telnetlib.Telnet(self.target, self.port, timeout=TELNET_TIMEOUT)
            telnet_client.expect([b"Login: ", b"login: ", b"Username: ", b"username: "], 5)
            telnet_client.close()

            return True
        except Exception:
            pass

        return False

    def telnet_interactive(self, telnet):
        telnet.interact()

    def telnet_read_until(self, telnet_client, data):
        if telnet_client:
            if type(data) is str:
                data = bytes(data, "utf-8")

            response = telnet_client.read_until(data, 5)
            return str(response, "utf-8")

        return None

    def telnet_write(self, telnet_client, data):
        if telnet_client:
            if type(data) is str:
                data = bytes(data, "utf-8")

            return telnet_client.write(data, 5)

        return None

    def telnet_close(self, telnet_client):
        if telnet_client:
            telnet_client.close()

        return None
