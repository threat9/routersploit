from routersploit.modules.creds.generic.http_basic_digest_default import Exploit


def test_check_success(generic_target):
    """ Test scenerio - testing against HTTP server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.threads == 8
    assert type(exploit.defaults) is list
    assert exploit.path == "/"
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True
