import time
import binascii
from bluepy.btle import Scanner, DefaultDelegate
from .btle_device import Device


class BTLEScanner(Scanner):
    """ Bluetooth Low Energy Scanner """

    def __init__(self, mac=None, iface=0):
        Scanner.__init__(self, iface)
        self.mac = mac

    def _decode_address(self, resp):
        addr = binascii.b2a_hex(resp["addr"][0]).decode("utf-8")
        return ":".join([addr[i: i + 2] for i in range(0, 12, 2)])

    def _find_or_create(self, addr):
        if addr in self.scanned:
            dev = self.scanned[addr]
        else:
            dev = Device(addr, self.iface)
            self.scanned[addr] = dev

        return dev

    def process(self, timeout=10.0):
        start = time.time()

        while True:
            if timeout:
                remain = start + timeout - time.time()
                if remain <= 0.0:
                    break
            else:
                remain = None

            resp = self._waitResp(["scan", "stat"], remain)
            if resp is None:
                break

            respType = resp["rsp"][0]

            if respType == "stat":
                if resp["state"][0] == "disc":
                    self._mgmtCmd("scan")

            elif respType == "scan":
                addr = self._decode_address(resp)

                if not self.mac or addr == self.mac:
                    dev = self._find_or_create(addr)

                    newData = dev._update(resp)

                    if self.delegate:
                        self.delegate.handleDiscovery(dev, (dev.updateCount <= 1), newData)

                    if self.mac and dev.addr == self.mac:
                        break


class ScanDelegate(DefaultDelegate):
    def __init__(self, options):
        DefaultDelegate.__init__(self)
        self.options = options

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if not isNewDev:
            return
        elif self.options.mac and dev.addr != self.options.mac:
            return

        if self.options.buffering:
            dev.print_info()
