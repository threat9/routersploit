from routersploit.modules.creds.cameras.sentry360.ssh_default_creds import Exploit


def test_check_success(target):
    """ Test scenario - testing against SSH server """

    exploit = Exploit()
    assert exploit.target == ""
    assert exploit.port == 22
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:1234"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
