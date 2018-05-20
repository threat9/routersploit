from routersploit.modules.creds.generic.telnet_bruteforce import Exploit


def test_check_success(generic_target):
    """ Test scenario - successful check """

    exploit = Exploit()
    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is True
    assert exploit.check_default() is not None
    assert exploit.run() is None
