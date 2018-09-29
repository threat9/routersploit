from routersploit.modules.exploits.routers.cisco.ucm_info_disclosure import Exploit


def test_check_success(udp_target):
    """ Test scenario - successful check """

    command_mock = udp_target.get_command_mock(b"\x00\x01SPDefault.cnf.xml\x00netascii\x00")
    command_mock.return_value = b"TEST UseUserCredential Test"

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 69

    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.check()
    assert exploit.run() is None
