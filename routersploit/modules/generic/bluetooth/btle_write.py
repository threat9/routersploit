from routersploit.core.exploit import *
from routersploit.core.bluetooth.btle_client import BTLEClient


class Exploit(BTLEClient):
    __info__ = {
        "name": "Bluetooth LE Write",
        "description": "Writes data to target Bluetooth Low Energy device to given "
                       "characteristic.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/",
        ),
    }

    target = OptMAC("", "Target MAC address")
    char = OptString("", "Characteristic")
    data = OptString("41424344", "Data (in hex format)")
    buffering = OptBool(True, "Buffering enabled: true/false. Results in real time.")

    def run(self):
        try:
            data = bytes.fromhex(self.data)
        except ValueError:
            print_error("Data is not in valid format")
            return

        res = self.btle_scan(self.target)
        if res:
            device = res[0]
            device.write(self.char, data)
