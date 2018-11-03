from pysnmp.entity.rfc3413.oneliner import cmdgen

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error


SNMP_TIMEOUT = 15.0


class SNMPCli(object):
    """ SNMP Client provides methods to handle communication with SNMP server """

    def __init__(self, snmp_target: str, snmp_port: int, verbosity: bool = False) -> None:
        """ SNMP client constructor

        :param str snmp_target: target SNMP server ip address
        :param port snmp_port: target SNMP server port
        :param bool verbosity: display verbose output
        :return None:
        """

        self.snmp_target = snmp_target
        self.snmp_port = snmp_port
        self.verbosity = verbosity

        self.peer = "{}:{}".format(self.snmp_target, snmp_port)

    def get(self, community_string: str, oid: str, version: int = 1, retries: int = 0) -> bytes:
        """ Get OID from SNMP server

        :param str community_string: SNMP server communit string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """

        cmdGen = cmdgen.CommandGenerator()

        try:
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData(community_string, mpModel=version),
                cmdgen.UdpTransportTarget((self.snmp_target, self.snmp_port), timeout=SNMP_TIMEOUT, retries=retries),
                oid,
            )
        except Exception as err:
            print_error(self.peer, "SNMP Error while accessing server", err, verbose=self.verbosity)
            return None

        if errorIndication or errorStatus:
            print_error(self.peer, "SNMP invalid community string: '{}'".format(community_string), verbose=self.verbosity)
        else:
            print_success(self.peer, "SNMP valid community string found: '{}'".format(community_string), verbose=self.verbosity)
            return varBinds

        return None


class SNMPClient(Exploit):
    """ SNMP Client exploit """

    target_protocol = Protocol.SNMP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def snmp_create(self, target: str = None, port: int = None) -> SNMPCli:
        """ Create SNMP client

        :param str target: target SNMP server ip address
        :param int port: target SNMP server port
        :return SNMPCli: SNMP client object
        """

        snmp_target = target if target else self.target
        snmp_port = port if port else self.port

        snmp_client = SNMPCli(snmp_target, snmp_port, verbosity=self.verbosity)
        return snmp_client
