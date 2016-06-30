import socket
import urlparse

from .exceptions import OptionValidationError


def url(address):
    """Sanitize url.

    Converts address to valid HTTP url.
    """
    if address.startswith("http://") or address.startswith("https://"):
        return address
    else:
        return "http://{}".format(address)


def address(addr):
    addr = urlparse.urlsplit(addr)
    return addr.netloc or address.path


def ipv4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            raise OptionValidationError("Option have to be valid IP address.")

        if address.count('.') == 3:
            return address
        else:
            raise OptionValidationError("Option have to be valid IP address.")
    except socket.error:
        raise OptionValidationError("Option have to be valid IP address.")

    return address
