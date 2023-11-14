import re

from routersploit.core.exploit import *
from routersploit.core.udp.udp_client import UDPClient


class Exploit(UDPClient):
    __info__ = {
        "name": "SSDP M-SEARCH Info Discovery",
        "description": "Sends M-SEARCH request to target and retrieve information from UPnP "
                       "enabled systems.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.upnp-hacks.org/upnp.html",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6")
    port = OptPort(1900, "Target UPNP Port")

    def run(self):
        request = (
            "M-SEARCH * HTTP/1.1\r\n"
            + f"HOST: {self.target}:{self.port}\r\n"
            + "MAN: \"ssdp:discover\"\r\n"
            + "MX: 2\r\n"
            + "ST: upnp:rootdevice\r\n\r\n"
        )
        request = bytes(request, "utf-8")

        udp_client = self.udp_create()
        udp_client.send(request)

        if response := udp_client.recv(1024):
            response = str(response, "utf-8")

            info = {}
            regexps = {
                "server": r"Server:\s*(.*?)\r\n",
                "location": r"Location:\s*(.*?)\r\n",
                "usn": r"USN:\s*(.*?)\r\n",
            }

            for key, value in regexps.items():
                if res := re.findall(value, response, re.IGNORECASE):
                    info[key] = res[0]
                else:
                    info[key] = ""

            print_status(
                f'{self.target}:{self.port} | {info["server"]} | {info["location"]} | {info["usn"]}'
            )
        else:
            print_error("Target did not respond to M-SEARCH request")

        udp_client.close()
