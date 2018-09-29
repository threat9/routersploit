from routersploit.modules.creds.routers.dlink.ssh_default_creds import Exploit


def test_check_success(generic_target):
    """ Test scenario - testing against SSH server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 22
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:admin", "1234:1234", "root:12345", "root:root"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
