from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.netgear.multi_rce import Exploit


def apply_response_v1(*args, **kwargs):
    res = request.args['macAddress']
    data = "Update Success! TEST" + res + "TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.netgear.multi_rce.shell")
def test_exploit_v1_success(mocked_shell, target):
    """ Test scenario - successful exploitation via method 1 """

    route_mock = target.get_route_mock("/boardData102.php", methods=["GET"])
    route_mock.side_effect = apply_response_v1

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


def apply_response_v2(*args, **kwargs):
    res = request.args['macAddress']
    data = "Update Success! TEST" + res + "TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.netgear.multi_rce.shell")
def test_exploit_v2_success(mocked_shell, target):
    """ Test scenario - successful exploitation via method 2 """

    route_mock = target.get_route_mock("/boardDataNA.php", methods=["GET"])
    route_mock.side_effect = apply_response_v2

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


def apply_response_v3(*args, **kwargs):
    res = request.args['macAddress']
    data = "Update Success! TEST" + res + "TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.netgear.multi_rce.shell")
def test_exploit_v3_success(mocked_shell, target):
    """ Test scenario - successful exploitation via method 3 """

    route_mock = target.get_route_mock("/boardDataWW.php", methods=["GET"])
    route_mock.side_effect = apply_response_v3

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


def apply_response_v4(*args, **kwargs):
    res = request.args['macAddress']
    data = "Update Success! TEST" + res + "TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.netgear.multi_rce.shell")
def test_exploit_v4_success(mocked_shell, target):
    """" Test scenario - successful exploitation via method 4 """

    route_mock = target.get_route_mock("/boardDataJP.php", methods=["GET"])
    route_mock.side_effect = apply_response_v4

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


def apply_response_v5(*args, **kwargs):
    res = request.args['macAddress']
    data = "Update Success! TEST" + res + "TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.netgear.multi_rce.shell")
def test_exploit_v5_success(mocked_shell, target):
    """ Test scenario - successful exploitation via method 5 """

    route_mock = target.get_route_mock("/boardDataJP.php", methods=["GET"])
    route_mock.side_effect = apply_response_v5

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
