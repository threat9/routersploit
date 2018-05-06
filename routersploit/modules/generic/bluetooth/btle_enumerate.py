from routersploit.core.exploit import *
from routersploit.core.bluetooth.btle_client import BTLEClient


class Exploit(BTLEClient):
    __info__ = {
        "name": "Bluetooth LE Enumerate",
        "description": "Enumerating services and characteristics of a given "
                       "Bluetooth Low Energy devices.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/",
        ),
    }

    target = OptMAC("", "Target MAC address")

    def run(self):
        res = self.btle_scan(self.target)
        if res:
            device = res[0]

            device.print_info()
            device.print_services()
