from routersploit.modules.creds.cameras.jvc.telnet_default_creds import Exploit


def test_check_success(generic_target):
    """ Test scenario - testing against Telnet server """

    exploit = Exploit()
    assert exploit.target == ""
    assert exploit.port == 23
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:jvc"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is True
    assert exploit.check_default() is not None
    assert exploit.run() is None
