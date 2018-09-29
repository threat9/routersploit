from flask import request
from routersploit.modules.creds.cameras.acti.webinterface_http_form_default_creds import Exploit


def apply_response(*args, **kwargs):
    if request.method == "GET":
        return "<TEST>Password</TEST>", 200
    elif request.method == "POST":
        return "TEST", 200


def test_check_success(target):
    """ Test scenario - testing against HTTP server """

    route_mock = target.get_route_mock("/video.htm", methods=["GET", "POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.threads == 1
    assert exploit.defaults == ["admin:12345", "admin:123456", "Admin:12345", "Admin:123456"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is True
    assert exploit.check_default() is not None
    assert exploit.run() is None
