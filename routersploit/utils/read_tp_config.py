#!/usr/bin/env python
# decrypt tp-link config.bin file

from Crypto.Cipher import DES


def decrypt_authKey(authKey):
    matrix = [[0 for i in xrange(15)] for i in range(15)]
    passwdLen = 0
    strDe = "RDpbLfCPsJZ7fiv"
    dic = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
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


def parse(data):
    l = data.split('\r\n')
    del l[0]
    for item in l:
        try:
            if 'authKey' in item:
                authKey = item.split()[1]
            if 'cPskSecret' in item:
                cPskSecret = item.split()[1]
            if 'cUsrPIN' in item:
                cUsrPIN = item.split()[1]
        except:
            pass
    return authKey, cPskSecret, cUsrPIN


def decrypt_config_bin(data):
    key = '\x47\x8D\xA5\x0B\xF9\xE3\xD2\xCF'
    crypto = DES.new(key, DES.MODE_ECB)
    data_decrypted = crypto.decrypt(data).rstrip('\0')
    authKey, cPskSecret, cUsrPIN = parse(data_decrypted)
    passwd = decrypt_authKey(authKey)
    return passwd, authKey, cPskSecret, cUsrPIN
