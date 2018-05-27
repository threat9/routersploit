from routersploit.modules.creds.generic.ftp_bruteforce import Exploit


def test_check_success(generic_target):
    """ Test scenario - testing against Telnet server """

    exploit = Exploit()
    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
