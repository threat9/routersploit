from routersploit.modules.creds.cameras.avigilon.ssh_default_creds import Exploit


def test_check_success(target):
    """ Test scenario - testing against HTTP server """

    exploit = Exploit()
    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
