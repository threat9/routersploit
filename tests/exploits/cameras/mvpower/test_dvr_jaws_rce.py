import re
from unittest import mock
from flask import request
from routersploit.modules.exploits.cameras.mvpower.dvr_jaws_rce import Exploit


def apply_response(*args, **kwargs):
    cmd = request.query_string
    res = re.findall(b"echo%20(.+)", cmd)

    if res:
        return str(res[0], "utf-8"), 200

    return "WRONG", 200


@mock.patch("routersploit.modules.exploits.cameras.mvpower.dvr_jaws_rce.shell")
def test_exploit_success(mocked_shell, target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/shell", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
