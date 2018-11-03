from unittest import mock
from flask import request
from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.linksys.1500_2500_rce")


def apply_response(*args, **kwargs):
    data = "TEST" + request.form["ping_size"] + "TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.linksys.1500_2500_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/apply.cgi", methods=["POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.username == "admin"
    assert exploit.password == "admin"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
