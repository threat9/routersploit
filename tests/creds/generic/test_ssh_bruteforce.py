from routersploit.modules.creds.generic.ssh_bruteforce import Exploit


def test_check_success(generic_target):
    """ Test scenario - testing against SSH server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 22
    assert exploit.threads == 8
    assert exploit.usernames == ["admin"]
    assert type(exploit.passwords) is list
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
