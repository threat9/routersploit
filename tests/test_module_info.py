import pytest
from routersploit.core.exploit.utils import iter_modules


@pytest.mark.parametrize("exploit", iter_modules("./routersploit/modules/exploit"))
def test_exploit_info(exploit):
    info = exploit._Exploit__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)

    assert "references" in info
    assert isinstance(info["references"], tuple)

    assert "devices" in info
    assert isinstance(info["devices"], tuple)


@pytest.mark.parametrize("creds", iter_modules("./routersploit/modules/creds"))
def test_creds_info(creds):
    info = creds._Exploit__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)

    assert "devices" in info
    assert isinstance(info["devices"], tuple)


@pytest.mark.parametrize("scanner", iter_modules("./routersploit/modules/scanners"))
def test_scanner_info(scanner):
    info = scanner._Exploit__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)

    assert "devices" in info
    assert isinstance(info["devices"], tuple)


@pytest.mark.parametrize("payload", iter_modules("./routersploit/modules/payloads"))
def test_payload_info(payload):
    info = payload._Payload__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)


@pytest.mark.parametrize("encoder", iter_modules("./routersploit/modules/encoders"))
def test_encoder_info(encoder):
    info = encoder._Encoder__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)
