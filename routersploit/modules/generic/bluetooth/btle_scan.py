from routersploit.core.exploit import *
from routersploit.core.bluetooth.btle_client import BTLEClient


class Exploit(BTLEClient):
    __info__ = {
        "name": "Bluetooth LE Scan",
        "description": "Scans for Bluetooth Low Energy devices.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/",
        ),
    }

    enum = OptBool(False, "Automatically enumerate services: true/false")
    buffering = OptBool(False, "Buffering enabled: true/false. Results in real time.")

    def run(self):
        devices = self.btle_scan()

        for device in devices:
            if not self.buffering:
                device.print_info()

            if self.enum:
                device.print_services()
