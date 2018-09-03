from pysnmp.entity.rfc3413.oneliner import cmdgen

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error


SNMP_TIMEOUT = 15.0


class SNMPCli(object):
    def __init__(self, snmp_target, snmp_port, verbosity=False):
        self.snmp_target = snmp_target
        self.snmp_port = snmp_port
        self.verbosity = verbosity

    def get(self, community_string, oid, version=1, retries=0):
        cmdGen = cmdgen.CommandGenerator()

        try:
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData(community_string, mpModel=version),
                cmdgen.UdpTransportTarget((self.snmp_target, self.snmp_port), timeout=SNMP_TIMEOUT, retries=retries),
                oid,
            )
        except Exception as err:
            print_error("SNMP error", err, verbose=self.verbosity)
            return None

        if errorIndication or errorStatus:
            print_error("SNMP invalid community string: '{}'".format(community_string), verbose=self.verbosity)
        else:
            print_success("SNMP valid community string found: '{}'".format(community_string), verbose=self.verbosity)
            return varBinds

        return None


class SNMPClient(Exploit):
    """ SNMP Client exploit """

    target_protocol = Protocol.SNMP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def snmp_create(self, target=None, port=None):
        snmp_target = target if target else self.target
        snmp_port = port if port else self.port

        snmp_client = SNMPCli(snmp_target, snmp_port, verbosity=self.verbosity)
        return snmp_client
