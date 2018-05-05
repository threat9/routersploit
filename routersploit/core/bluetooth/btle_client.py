from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.option import OptInteger
from routersploit.core.exploit.printer import (
    print_error,
    print_status
)
from routersploit.core.bluetooth.btle import (
    ScanDelegate,
    BTLEScanner
)


class Options:
    """ Options used by the scanner """

    def __init__(self, buffering, mac, enum_services):
        self.buffering = buffering
        self.mac = mac
        self.enum_services = enum_services


class BTLEClient(Exploit):
    """ Bluetooth Low Energy Client implementation """

    scan_time = OptInteger(10, "Number of seconds to scan for")
    buffering = False
    enum_services = False

    def btle_scan(self, mac=None):
        """ Scans for Bluetooth Low Energy devices """

        options = Options(
            self.buffering,
            mac,
            self.enum_services
        )

        scanner = BTLEScanner(options.mac).withDelegate(ScanDelegate(options))

        if options.mac:
            print_status("Scanning BTLE device...")
        else:
            print_status("Scanning for BTLE devices...")

        devices = []
        try:
            devices = [res for res in scanner.scan(self.scan_time)]
        except Exception as err:
            print_error("Error: {}".format(err))
            print_error("Check if your bluetooth hardware is connected")

        return devices
