from base64 import b64encode
from routersploit.core.exploit.encoders import BaseEncoder
from routersploit.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Python Base64 Encoder",
        "description": "aaa",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PYTHON

    def encode(self, payload):
        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "exec('{}'.decode('base64'))".format(encoded_payload)
