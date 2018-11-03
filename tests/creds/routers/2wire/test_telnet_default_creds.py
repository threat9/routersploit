from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.creds.routers.2wire.telnet_default_creds")


def test_check_success(generic_target):
    """ Test scenario - testing against Telnet server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 23
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:admin"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is True
    assert exploit.check_default() is not None
    assert exploit.run() is None
