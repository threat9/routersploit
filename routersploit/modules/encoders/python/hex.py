from routersploit.core.exploit.encoders import BaseEncoder
from routersploit.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Python Hex Encoder",
        "description": "Module encodes Python payload to Hex format.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PYTHON

    def encode(self, payload):
        encoded_payload = bytes(payload, "utf-8").hex()
        return "exec('{}'.decode('hex'))".format(encoded_payload)
