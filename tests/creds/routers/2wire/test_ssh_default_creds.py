from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.creds.routers.2wire.ssh_default_creds")


def test_check_success(target):
    """ Test scenario - testing against SSH server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 22
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:admin"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
