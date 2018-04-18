import socket
import urlparse
from distutils.util import strtobool

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
    return addr.netloc or addr.path


def choice(valid_values):
    valid_values = [] if not valid_values else valid_values

    def _enum(value):
        if value not in valid_values:
            raise OptionValidationError(
                "Selected '{}' value isn't correct. "
                "Possible values are: {}".format(value, valid_values)
            )

        return value

    return _enum


def ipv4(address):
    address = address.replace("http://", "").replace("https://", "")

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


def boolify(value):
    """ Function that will translate common strings into bool values

    True -> "True", "t", "yes", "y", "on", "1"
    False -> any other string

    Objects other than string will be transformed
    using built-in bool() function.
    """
    if isinstance(value, basestring):
        try:
            return bool(strtobool(value))
        except ValueError:
            return False
    else:
        return bool(value)


def integer(number):
    """ Cast Option value to the integer using int() """
    try:
        return int(number)
    except ValueError:
        raise OptionValidationError(
            "Invalid option. can't cast '{}' to integer.".format(number)
        )


def convert_ip(address):
    """ Convert IP to bytes"""
    try:
        res = ""
        for i in address.split("."):
            res += chr(int(i))
        return res
    except Exception:
        raise OptionValidationError(
            "Invalid option. '{}' is not a valid IP address".format(address)
        )


def convert_port(port):
    """ Convert Port to bytes"""
    try:
        res = "%.4x" % int(port)
        return res.decode('hex')
    except Exception:
        raise OptionValidationError(
            "Invalid option. '{}' is not a valid port number".format(port)
        )
