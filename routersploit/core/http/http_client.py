import socket
import requests
import urllib3

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_TIMEOUT = 30.0


class HTTPClient(Exploit):
    """ HTTP Client provides methods to handle communication with HTTP server """

    target_protocol = Protocol.HTTP

    verbosity = OptBool(True, "Verbosity enabled: true/false")
    ssl = OptBool(False, "SSL enabled: true/false")

    def http_request(self, method: str, path: str, session: requests = requests, **kwargs) -> requests.Response:
        """ Requests HTTP resource

        :param str method: method that should be issued e.g. GET, POST
        :param str path: path to the resource that should be requested
        :param requests session: session manager that should be used
        :param kwargs: kwargs passed to request method
        :return Response: Response object
        """

        if self.ssl:
            url = "https://"
        else:
            url = "http://"

        url += "{}:{}{}".format(self.target, self.port, path)

        kwargs.setdefault("timeout", HTTP_TIMEOUT)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)

        try:
            return getattr(session, method.lower())(url, **kwargs)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            print_error("Invalid URL format: {}".format(url), verbose=self.verbosity)
        except requests.exceptions.ConnectionError:
            print_error("Connection error: {}".format(url), verbose=self.verbosity)
        except requests.RequestException as error:
            print_error(error, verbose=self.verbosity)
        except socket.error as err:
            print_error(err, verbose=self.verbosity)
        except KeyboardInterrupt:
            print_error("Module has been stopped", verbose=self.verbosity)

        return None

    def get_target_url(self, path: str = "") -> str:
        """ Get target URL

        :param str path: path to http server resource
        :return str: full target url with correct schema
        """

        if self.ssl:
            url = "https://"
        else:
            url = "http://"

        url += "{}:{}{}".format(self.target, self.port, path)

        return url

    def http_test_connect(self) -> bool:
        """ Test connection to HTTP server

        :return bool: True if test connection was successful, False otherwise
        """

        response = self.http_request(
            method="GET",
            path="/"
        )

        if response:
            return True

        return False
