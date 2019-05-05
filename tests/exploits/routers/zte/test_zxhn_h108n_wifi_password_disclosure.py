from routersploit.modules.exploits.routers.zte.zxhn_h108n_wifi_password_disclosure import Exploit


def test_check_succecc(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/wizard_wlan_t.gch", methods=["GET"])
    route_mock.return_value = (
        "(..)"
        "<script language=javascript>Transfer_meaning('PreSharedKey','');</script>"
        "<INPUT type='hidden' name=KeyPassphrase   ID=KeyPassphrase value=''>"
        "<script language=javascript>Transfer_meaning('KeyPassphrase','');</script>"
        "<INPUT type='hidden' name=AssociatedDeviceMACAddress   ID=AssociatedDeviceMACAddress value=''>"
        "<script language=javascript>Transfer_meaning('AssociatedDeviceMACAddress','');</script>"
        "<script language=javascript>Transfer_meaning('IF_ERRORSTR','SUCC');</script>"
        "<script language=javascript>Transfer_meaning('IF_ERRORPARAM','SUCC');</script>"
        "<script language=javascript>Transfer_meaning('IF_ERRORTYPE','\x2d1');</script>"
        "<script language=javascript>Transfer_meaning('PreSharedKey','');</script>"
        "<script language=javascript>Transfer_meaning('KeyPassphrase','Password');</script>"
        "<script language=javascript>Transfer_meaning('AssociatedDeviceMACAddress','00\x3a00\x3a00\x3a00\x3a00\x3a00');</script>"
        "<script language=javascript>Transfer_meaning('IF_ERRORSTR','SUCC');</script>"
        "<script language=javascript>Transfer_meaning('IF_ERRORPARAM','SUCC');</script>"
        "(..)"
        "<script language=javascript>Transfer_meaning('CardIsIn','1');</script>"
        "<script language=javascript>Transfer_meaning('MaxInterface','4');</script>"
        "<script language=javascript>Transfer_meaning('DeviceMode','InfrastructureAccessPoint');</script>"
        "<script language=javascript>Transfer_meaning('CardMode','b\x2cg\x2cn\x2cbg\x2cgn\x2cbgn');</script>"
        "<script language=javascript>Transfer_meaning('CardRev','0');</script>"
        "<script language=javascript>Transfer_meaning('Class','255');</script>"
        "<script language=javascript>Transfer_meaning('PID','33169');</script>"
        "<script language=javascript>Transfer_meaning('VID','4332');</script>"
        "<script language=javascript>Transfer_meaning('ValidIf','1');</script>"
        "<script language=javascript>Transfer_meaning('Enable','1');</script>"
        "<script language=javascript>Transfer_meaning('RadioStatus','1');</script>"
        "<script language=javascript>Transfer_meaning('Standard','b\x2cg\x2cn');</script>"
        "<script language=javascript>Transfer_meaning('BeaconInterval','100');</script>"
        "<script language=javascript>Transfer_meaning('RtsCts','2347');</script>"
        "<script language=javascript>Transfer_meaning('Fragment','2346');</script>"
        "<script language=javascript>Transfer_meaning('DTIM','1');</script>"
        "<script language=javascript>Transfer_meaning('TxPower','100\x25');</script>"
        "<script language=javascript>Transfer_meaning('CountryCode','egI');</script>"
        "<script language=javascript>Transfer_meaning('TxRate','Auto');</script>"
        "<script language=javascript>Transfer_meaning('Channel','1');</script>"
        "<script language=javascript>Transfer_meaning('ESSID','SSID Name');</script>"
        "<script language=javascript>Transfer_meaning('ESSIDPrefix','');</script>"
        "<script language=javascript>Transfer_meaning('ACLPolicy','Disabled');</script>"
        "<script language=javascript>Transfer_meaning('BeaconType','WPAand11i');</script>"
        "(..)"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
