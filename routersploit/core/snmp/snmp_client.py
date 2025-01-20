import asyncio
from pysnmp.hlapi.v3arch.asyncio import *

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error


SNMP_TIMEOUT = 15.0


class SNMPCli:
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

        :param str community_string: SNMP server community string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """

        return asyncio.run(self.get_cmd(
            community_string,
            oid,
            version,
            retries
        ))

    async def get_cmd(self, community_string: str, oid: str, version: int, retries: int):
        """ Retrieves OID from SNMP server

        :param str community_string: SNMP server community string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """

        snmpEngine = SnmpEngine()

        iterator = get_cmd(
            snmpEngine,
            CommunityData(community_string, mpModel=version),
            await UdpTransportTarget.create((self.snmp_target, self.snmp_port), timeout=SNMP_TIMEOUT, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        errorIndication, errorStatus, errorIndex, varBinds = await iterator
        snmpEngine.close_dispatcher()

        if errorIndication or errorStatus:
            print_error(self.peer, "SNMP invalid community string: '{}'".format(community_string), verbose=self.verbosity)
        else:
            print_success(self.peer, "SNMP valid community string found: '{}'".format(community_string), verbose=self.verbosity)
            return varBinds

        return None


# pylint: disable=no-member
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
