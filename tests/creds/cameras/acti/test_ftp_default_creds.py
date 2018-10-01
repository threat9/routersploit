from routersploit.modules.creds.cameras.acti.ftp_default_creds import Exploit


def test_check_success(generic_target):
    """ Test scenario - testing against FTP server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 21
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:12345", "admin:123456", "Admin:12345", "Admin:123456"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = generic_target.host
    exploit.port = generic_target.port

    assert exploit.check() is False
    assert exploit.check_default() is None
    assert exploit.run() is None
