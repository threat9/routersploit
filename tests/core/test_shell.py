from routersploit.core.exploit.shell import Communication


def test_communication_default_wget_options_not_shared():
    communication_1 = Communication(None, "", [])
    communication_2 = Communication(None, "", [])

    assert communication_1.wget_options is not communication_2.wget_options


def test_communication_default_echo_options_not_shared():
    communication_1 = Communication(None, "", [])
    communication_2 = Communication(None, "", [])

    assert communication_1.echo_options is not communication_2.echo_options


def test_communication_default_options_mutation_is_isolated():
    communication_1 = Communication(None, "", [])
    communication_2 = Communication(None, "", [])

    communication_1.wget_options["binary"] = "/tmp/payload"
    communication_1.echo_options["prefix"] = "\\\\x"

    assert "binary" not in communication_2.wget_options
    assert "prefix" not in communication_2.echo_options


def test_communication_explicit_none_options():
    communication = Communication(None, "", [], wget_options=None, echo_options=None)

    assert communication.wget_options == {}
    assert communication.echo_options == {}
