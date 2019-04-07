import struct
from bluepy.btle import (
    Peripheral,
    ScanEntry,
    AssignedNumbers
)
from routersploit.core.exploit.printer import (
    print_table,
    print_success,
    print_status,
    print_error,
    color_blue,
    color_green,
    color_red
)
from routersploit.core.exploit.utils import (
    lookup_vendor
)


class Device(ScanEntry):
    """ Single discovered Bluetooth Low Energy device """

    def __init__(self, addr, iface):
        ScanEntry.__init__(self, addr, iface)

        self.vendor = None
        self.data = []

    def _update(self, resp):
        ScanEntry._update(self, resp)

        if self.addrType == "random":
            self.vendor = "None (Random MAC address)"
        else:
            self.vendor = lookup_vendor(self.addr)

        if self.scanData:
            self.data = self._get_data(self.getScanData())

    def print_info(self):
        headers = (color_blue("{} ({} dBm)").format(self.addr, self.rssi), "")
        if self.connectable:
            allow_connection = color_green(str(self.connectable))
        else:
            allow_connection = color_red(str(self.connectable))

        data = [
            ("Vendor", self.vendor),
            ("Allow Connections", allow_connection),
        ]

        for d in self.data:
            data.append((d[0], d[1]))

        print_table(headers, *data, max_column_length=70, extra_fill=3)

    def print_services(self):
        headers = ("Handles", "Service > Characteristics", "Properties", "Data")
        services = self.enumerate_services()

        if services:
            print_table(headers, *services, max_column_length=70, extra_fill=3)

    def enumerate_services(self):
        print_status("Starting enumerating {} ({} dBm) ...".format(self.addr, self.rssi))

        try:
            dev = Peripheral(self, self.addrType)

            services = sorted(dev.services, key=lambda s: s.hndStart)

            data = []
            for service in services:
                if service.hndStart == service.hndEnd:
                    continue

                data.append([
                    "{:04x} -> {:04x}".format(service.hndStart, service.hndEnd),
                    self._get_svc_description(service),
                    "",
                    "",
                ])

                for _, char in enumerate(service.getCharacteristics()):
                    desc = self._get_char_description(char)
                    props = char.propertiesToString()
                    hnd = char.getHandle()
                    value = self._get_char(char, props)

                    data.append([
                        "{:04x}".format(hnd), desc, props, value
                    ])

            dev.disconnect()

            return data

        except Exception as err:
            print_error(err)

        try:
            dev.disconnect()
        except Exception as err:
            print_error(err)

        return None

    def write(self, characteristic, data):
        try:
            dev = Peripheral(self, self.addrType)

            services = sorted(dev.services, key=lambda s: s.hndStart)

            print_status("Searching for characteristic {}".format(characteristic))
            char = None
            for service in services:
                if char is not None:
                    break

                for _, c in enumerate(service.getCharacteristics()):
                    if str(c.uuid) == characteristic:
                        char = c
                        break

            if char:
                if "WRITE" in char.propertiesToString():
                    print_success("Sending {} bytes...".format(len(data)))

                    wwrflag = False

                    if "NO RESPONSE" in char.propertiesToString():
                        wwrflag = True

                    try:
                        char.write(data, wwrflag)
                        print_success("Data sent")
                    except Exception as err:
                        print_error("Error: {}".format(err))

                else:
                    print_error("Not writable")

            dev.disconnect()

        except Exception as err:
            print_error(err)

        try:
            dev.disconnect()
        except Exception:
            pass

        return None

    def _get_data(self, scan_data):
        data = []
        for (tag, desc, val) in scan_data:
            if desc == "Flags":
                data.append(("Flags", self._get_flags(val)))

            elif tag in [8, 9]:
                try:
                    data.append((desc, val))
                except UnicodeEncodeError:
                    data.append((desc, repr(val)))

            else:
                data.append((desc, val))

        return data

    def _get_flags(self, data):
        bits = []
        flags = int(data, 16)

        if self._is_bit_set(flags, 0):
            bits.append("LE Limited Discoverable")

        if self._is_bit_set(flags, 1):
            bits.append("LE General Discoverable")

        if self._is_bit_set(flags, 2):
            bits.append("BR/EDR")

        if self._is_bit_set(flags, 3):
            bits.append("LE + BR/EDR Controller Mode")

        if self._is_bit_set(flags, 4):
            bits.append("LE + BR/EDR Host Mode")

        return ", ".join(bits)

    def _is_bit_set(self, byteval, idx):
        return ((byteval & (1 << idx)) != 0)

    def _get_svc_description(self, service):
        uuid_name = service.uuid.getCommonName()

        if uuid_name and uuid_name != str(service.uuid):
            return "{} ({})".format(color_green(uuid_name), service.uuid)

        return str(service.uuid)

    def _get_char_description(self, char):
        char_name = char.uuid.getCommonName()
        if char_name and char_name != str(char.uuid):
            return "  {} ({})".format(color_green(char_name), char.uuid)

        return "  {}".format(char.uuid)

    def _get_char(self, char, props):
        string = ""
        if "READ" in props and "INDICATE" not in props:
            try:
                data = char.read()

                if char.uuid == AssignedNumbers.appearance:
                    string = self._get_appearance(data)
                else:
                    try:
                        string = color_blue(repr(data.decode("utf-8")))
                    except Exception:
                        string = repr(data)

            except Exception:
                pass

        return string

    def _get_appearance(self, data):
        appearance = {
            0: "Unknown",
            64: "Generic Phone",
            128: "Generic Computer",
            192: "Generic Watch",
            193: "Watch: Sports Watch",
            256: "Generic Clock",
            320: "Generic Display",
            384: "Generic Remote Control",
            448: "Generic Eye-glasses",
            512: "Generic Tag",
            576: "Generic Keyring",
            640: "Generic Media Player",
            704: "Generic Barcode Scanner",
            768: "Generic Thermometer",
            769: "Thermometer: Ear",
            832: "Generic Heart rate Sensor",
            833: "Heart Rate Sensor: Heart Rate Belt",
            896: "Generic Blood Pressure",
            897: "Blood Pressure: Arm",
            898: "Blood Pressure: Wrist",
            960: "Human Interface Device (HID)",
            961: "Keyboard",
            962: "Mouse",
            963: "Joystick",
            964: "Gamepad",
            965: "Digitizer Tablet",
            966: "Card Reader",
            967: "Digital Pen",
            968: "Barcode Scanner",
            1024: "Generic Glucose Meter",
            1088: "Generic: Running Walking Sensor",
            1089: "Running Walking Sensor: In-Shoe",
            1090: "Running Walking Sensor: On-Shoe",
            1091: "Running Walking Sensor: On-Hip",
            1152: "Generic: Cycling",
            1153: "Cycling: Cycling Computer",
            1154: "Cycling: Speed Sensor",
            1155: "Cycling: Cadence Sensor",
            1156: "Cycling: Power Sensor",
            1157: "Cycling: Speed and Cadence Sensor",
            1216: "Generic Control Device",
            1217: "Switch",
            1218: "Multi-switch",
            1219: "Button",
            1220: "Slider",
            1221: "Rotary",
            1222: "Touch-panel",
            1280: "Generic Network Device",
            1281: "Access Point",
            1344: "Generic Sensor",
            1345: "Motion Sensor",
            1346: "Air Quality Sensor",
            1347: "Temperature Sensor",
            1348: "Humidity Sensor",
            1349: "Leak Sensor",
            1350: "Smoke Sensor",
            1351: "Occupancy Sensor",
            1352: "Contact Sensor",
            1353: "Carbon Monoxide Sensor",
            1354: "Carbon Dioxide Sensor",
            1355: "Ambient Light Sensor",
            1356: "Energy Sensor",
            1357: "Color Light Sensor",
            1358: "Rain Sensor",
            1359: "Fire Sensor",
            1360: "Wind Sensor",
            1361: "Proximity Sensor",
            1362: "Multi-Sensor",
            1408: "Generic Light Fixtures",
            1409: "Wall Light",
            1410: "Ceiling Light",
            1411: "Floor Light",
            1412: "Cabinet Light",
            1413: "Desk Light",
            1414: "Troffer Light",
            1415: "Pendant Light",
            1416: "In-ground Light",
            1417: "Flood Light",
            1418: "Underwater Light",
            1419: "Bollard with Light",
            1420: "Pathway Light",
            1421: "Garden Light",
            1422: "Pole-top Light",
            1423: "Spotlight",
            1424: "Linear Light",
            1425: "Street Light",
            1426: "Shelves Light",
            1427: "High-bay / Low-bay Light",
            1428: "Emergency Exit Light",
            1472: "Generic Fan",
            1473: "Ceiling Fan",
            1474: "Axial Fan",
            1475: "Exhaust Fan",
            1476: "Pedestal Fan",
            1477: "Desk Fan",
            1478: "Wall Fan",
            1536: "Generic HVAC",
            1537: "Thermostat",
            1600: "Generic Air Conditioning",
            1664: "Generic Humidifier",
            1728: "Generic Heating",
            1729: "Radiator",
            1730: "Boiler",
            1731: "Heat Pump",
            1732: "Infrared Heater",
            1733: "Radiant Panel Heater",
            1734: "Fan Heater",
            1735: "Air Curtain",
            1792: "Generic Access Control",
            1793: "Access Door",
            1794: "Garage Door",
            1795: "Emergency Exit Door",
            1796: "Access Lock",
            1797: "Elevator",
            1798: "Window",
            1799: "Entrance Gate",
            1856: "Generic Motorized Device",
            1857: "Motorized Gate",
            1858: "Awning",
            1859: "Blinds or Shades",
            1860: "Curtains",
            1861: "Screen",
            1920: "Generic Power Device",
            1921: "Power Outlet",
            1922: "Power Strip",
            1923: "Plug",
            1924: "Power Supply",
            1925: "LED Driver",
            1926: "Fluorescent Lamp Gear",
            1927: "HID Lamp Gear",
            1984: "Generic Light Source",
            1985: "Incandescent Light Bulb",
            1986: "LED Bulb",
            1987: "HID Lamp",
            1988: "Fluorescent Lamp",
            1989: "LED Array",
            1990: "Multi-Color LED Array",
            3136: "Generic: Pulse Oximeter",
            3137: "Fingertip",
            3138: "Wrist Worn",
            3200: "Generic: Weight Scale",
            3264: "Generic",
            3265: "Powered Wheelchair",
            3266: "Mobility Scooter",
            3328: "Generic",
            5184: "Generic: Outdoor Sports Activity",
            5185: "Location Display Device",
            5186: "Location and Navigation Display Device",
            5187: "Location Pod",
            5188: "Location and Navigation Pod",
        }

        try:
            code = struct.unpack("h", data)[0]

            if code in appearance.keys():
                return color_green(appearance[code])
        except Exception:
            pass

        return repr(data)
