from routersploit.modules.exploits.routers.huawei.e5331_mifi_info_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/api/wlan/security-settings", methods=["GET"])
    route_mock.return_value = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<response>'
        '<WifiAuthmode>WPA2-PSK</WifiAuthmode>'
        '<WifiBasicencryptionmodes>NONE</WifiBasicencryptionmodes>'
        '<WifiWpaencryptionmodes>AES</WifiWpaencryptionmodes>'
        '<WifiWepKey1>12345</WifiWepKey1>'
        '<WifiWepKey2>12345</WifiWepKey2>'
        '<WifiWepKey3>12345</WifiWepKey3>'
        '<WifiWepKey4>12345</WifiWepKey4>'
        '<WifiWepKeyIndex>1</WifiWepKeyIndex>'
        '<WifiWpapsk>XXXXX</WifiWpapsk>'
        '<WifiWpsenbl>0</WifiWpsenbl>'
        '<WifiWpscfg>1</WifiWpscfg>'
        '<WifiRestart>1</WifiRestart>'
        '</response>'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
