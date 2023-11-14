import contextlib
from routersploit.modules.encoders.php.hex import Encoder as PHPHexEncoder
from routersploit.core.exploit.exceptions import OptionValidationError
from routersploit.core.exploit.option import (
    OptIP,
    OptPort,
    OptInteger,
    OptFloat,
    OptBool,
    OptString,
    OptMAC,
    OptWordlist,
    OptEncoder,
)


def test_opt_ip():
    # Test OptIP creation
    opt_ip = OptIP("", "Test IP Description")
    assert opt_ip.description == "Test IP Description"
    assert opt_ip.display_value == ""
    assert opt_ip.value == ""
    assert opt_ip.__get__(None, None) == ""

    # Test OptIP setting to empty value
    opt_ip.__set__(None, "")
    assert opt_ip.value == ""
    assert opt_ip.display_value == ""
    assert opt_ip.__get__(None, None) == ""

    # Test OptIP setting to 192.168.1.1
    opt_ip.__set__(None, "192.168.1.1")
    assert opt_ip.value == "192.168.1.1"
    assert opt_ip.display_value == "192.168.1.1"
    assert opt_ip.__get__(None, None) == "192.168.1.1"

    # Test OptIP setting to InvalidIP value
    try:
        opt_ip.__set__(None, "InvalidIP")
        assert False
    except OptionValidationError:
        assert True


def test_opt_port():
    # Test OptPort creation
    opt_port = OptPort(80, "Test Port Description")
    assert opt_port.description == "Test Port Description"
    verify_opt_port_properties(opt_port, "80", 80)
    # Test OptPort setting to 4444
    opt_port.__set__(None, 4444)
    verify_opt_port_properties(opt_port, "4444", 4444)
    # Test OptPort setting to 0
    with contextlib.suppress(OptionValidationError):
        opt_port.__set__(None, 0)
        assert False
    # Test OptPort setting to 65536
    with contextlib.suppress(OptionValidationError):
        opt_port.__set__(None, 65536)
        assert False


def verify_opt_port_properties(opt_port, arg1, arg2):
    assert opt_port.display_value == arg1
    assert opt_port.value == arg2
    assert opt_port.__get__(None, None) == arg2


def test_opt_bool():
    # Test OptBool creation
    opt_bool = OptBool(True, "Test Bool Description")
    assert opt_bool.description == "Test Bool Description"
    assert_opt_bool_true(opt_bool)
    # Test OptBool setting to false
    opt_bool.__set__(None, "false")
    assert opt_bool.display_value == "false"
    assert not opt_bool.value
    assert not opt_bool.__get__(None, None)

    # Test OptBool setting to true
    opt_bool.__set__(None, "true")
    assert_opt_bool_true(opt_bool)
    # Test OptBool setting to invalid value
    with contextlib.suppress(OptionValidationError):
        opt_bool.__set__(None, "Invalid Value")
        assert False


def assert_opt_bool_true(opt_bool):
    assert opt_bool.display_value == "true"
    assert opt_bool.value
    assert opt_bool.__get__(None, None)


def test_opt_integer():
    # Test OptInteger creation
    opt_integer = OptInteger(4444, "Test Integer Description")
    assert opt_integer.description == "Test Integer Description"
    assert opt_integer.display_value == "4444"
    assert opt_integer.value == 4444
    assert opt_integer.__get__(None, None) == 4444

    # Test OptInteger setting to -1
    opt_integer.__set__(None, -1)
    assert opt_integer.display_value == "-1"
    assert opt_integer.value == -1
    assert opt_integer.__get__(None, None) == -1

    # Test OptInteger setting to 9999999
    opt_integer.__set__(None, 9999999)
    assert opt_integer.display_value == "9999999"
    assert opt_integer.value == 9999999
    assert opt_integer.__get__(None, None) == 9999999

    # Test OptInteger setting to 0
    opt_integer = OptInteger(0, "Test Integer with 0")
    assert opt_integer.display_value == "0"
    assert opt_integer.value == 0
    assert opt_integer.__get__(None, None) == 0

    # Test OptInteger setting to 0x100
    opt_integer.__set__(None, "0x100")
    assert opt_integer.display_value == "0x100"
    assert opt_integer.value == 0x100
    assert opt_integer.__get__(None, None) == 0x100

    # Test OptInteget setting to invalid value
    try:
        opt_integer.__set__(None, "Invalid Value")
        assert False
    except OptionValidationError:
        assert True


def test_opt_float():
    # Test OptFloat creation
    opt_float = OptFloat(3.14, "Test Float Description")
    assert opt_float.description == "Test Float Description"
    assert_opt_float_values(opt_float, "3.14", 3.14)
    # Test OptFloat setting to -1
    opt_float.__set__(None, -1)
    assert_opt_float_values(opt_float, "-1", -1)
    # Test OptFloat setting to 999.9999
    opt_float.__set__(None, 999.9999)
    assert_opt_float_values(opt_float, "999.9999", 999.9999)
    # Test OptFloat setting to invalid value
    with contextlib.suppress(OptionValidationError):
        opt_float.__set__(None, "Invalid Value")
        assert False


def assert_opt_float_values(opt_float, arg1, arg2):
    assert opt_float.display_value == arg1
    assert opt_float.value == arg2
    assert opt_float.__get__(None, None) == arg2


def test_opt_string():
    # Test OptString creation
    opt_string = OptString("Test", "Test String Description")
    assert opt_string.description == "Test String Description"
    assert_opt_string_value(opt_string, "Test")
    # Test OptString setting to "AAAABBBBCCCCDDDD"
    opt_string.__set__(None, "AAAABBBBCCCCDDDD")
    assert_opt_string_value(opt_string, "AAAABBBBCCCCDDDD")


def assert_opt_string_value(opt_string, arg1):
    assert opt_string.display_value == arg1
    assert opt_string.value == arg1
    assert opt_string.__get__(None, None) == arg1


def test_opt_mac():
    # Test OptMAC creation
    opt_mac = OptMAC("AA:BB:CC:DD:EE:FF", "Test MAC Description")
    assert opt_mac.description == "Test MAC Description"
    assert_opt_mac_value(opt_mac, "AA:BB:CC:DD:EE:FF")
    # Test OptMAC setting to dd:ee:ff:dd:ee:ff
    opt_mac.__set__(None, "dd:ee:ff:dd:ee:ff")
    assert_opt_mac_value(opt_mac, "dd:ee:ff:dd:ee:ff")
    # Test OptMAC setting to invalid value
    with contextlib.suppress(OptionValidationError):
        opt_mac.__set__(None, "Invalid Value")
        assert False


def assert_opt_mac_value(opt_mac, arg1):
    assert opt_mac.display_value == arg1
    assert opt_mac.value == arg1
    assert opt_mac.__get__(None, None) == arg1


def test_opt_wordlist():
    # Test OptWordlist creation
    opt_wordlist = OptWordlist("", "Test Wordlist Description")
    assert opt_wordlist.description == "Test Wordlist Description"
    assert opt_wordlist.display_value == ""
    assert opt_wordlist.value == ""
    assert opt_wordlist.__get__(None, None) == [""]

    # Test OptWordlist setting to admin,test
    opt_wordlist.__set__(None, "admin,test")
    assert opt_wordlist.display_value == "admin,test"
    assert opt_wordlist.value == "admin,test"
    assert opt_wordlist.__get__(None, None) == ["admin", "test"]


def test_opt_encoder():
    # Test OptEncoder creation
    opt_encoder = OptEncoder(PHPHexEncoder(), "Test Encoder Description")
    assert opt_encoder.description == "Test Encoder Description"
    assert str(opt_encoder.display_value) == "php/hex"
    assert type(opt_encoder.display_value) == PHPHexEncoder
