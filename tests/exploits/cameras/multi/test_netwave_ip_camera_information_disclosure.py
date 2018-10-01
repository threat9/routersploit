from routersploit.modules.exploits.cameras.multi.netwave_ip_camera_information_disclosure import Exploit


def test_check_v2_success(target):
    """ Test scenario - successful check via method 2 """

    route_mock = target.get_route_mock("/get_status.cgi", methods=["GET"])
    route_mock.return_value = (
        "var id='E8ABFA1BC72F';"
        "var sys_ver='17.37.2.49';"
        "var app_ver='20.8.1.166';"
        "var alias='Camera';"
        "var now=1509798733;"
        "var tz=0;"
        "var alarm_status=0;"
        "var ddns_status=40;"
        "var ddns_host='/vipddns/upgengxin.asp';"
        "var oray_type=0;"
        "var upnp_status=1;"
        "var p2p_status=0;"
        "var p2p_local_port=26296;"
        "var msn_status=0;"
        "var wifi_status=1;"
        "var temperature=0.0;"
        "var humidity=0;"
        "var tridro_error='';"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
