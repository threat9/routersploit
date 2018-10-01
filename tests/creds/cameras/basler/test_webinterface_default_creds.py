from routersploit.modules.creds.cameras.basler.webinterface_http_form_default_creds import Exploit


def test_check_success(target):
    """ Test scenario - testing against HTTP server """

    route_mock = target.get_route_mock("/cgi-bin/auth_if.cgi", methods=["GET", "POST"])
    route_mock.return_value = "success: true"

    exploit = Exploit()
    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:admin"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is True
    assert exploit.check_default() is not None
    assert exploit.run() is None
