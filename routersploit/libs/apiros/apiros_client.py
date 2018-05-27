import sys
import binascii
import hashlib


class ApiRosClient(object):
    "RouterOS API"

    def __init__(self, sk):
        self.sk = sk
        self.currenttag = 0

    def login(self, username, pwd):
        for repl, attrs in self.talk(["/login"]):
            chal = binascii.unhexlify((attrs['=ret']).encode('UTF-8'))
        md = hashlib.md5()
        md.update(b'\x00')
        md.update(pwd.encode('UTF-8'))
        md.update(chal)
        output = self.talk([
            "/login",
            "=name=" + username,
            "=response=00" + binascii.hexlify(md.digest()).decode('UTF-8')
        ])
        return output

    def talk(self, words):
        if self.writeSentence(words) == 0:
            return
        r = []
        while 1:
            i = self.readSentence()
            if len(i) == 0:
                continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[: j]] = w[j + 1:]
            r.append((reply, attrs))
            if reply == '!done':
                return r

    def writeSentence(self, words):
        ret = 0
        for w in words:
            self.writeWord(w)
            ret += 1
        self.writeWord('')
        return ret

    def readSentence(self):
        r = []
        while 1:
            w = self.readWord()
            if w == '':
                return r
            r.append(w)

    def writeWord(self, w):
        self.writeLen(len(w))
        self.writeStr(w)

    def readWord(self):
        ret = self.readStr(self.readLen())
        return ret

    def writeLen(self, length):
        if length < 0x80:
            self.writeByte((length).to_bytes(1, sys.byteorder))
        elif length < 0x4000:
            length |= 0x8000
            self.writeByte(((length >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((length & 0xFF).to_bytes(1, sys.byteorder))
        elif length < 0x200000:
            length |= 0xC00000
            self.writeByte(((length >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((length >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((length & 0xFF).to_bytes(1, sys.byteorder))
        elif length < 0x10000000:
            length |= 0xE0000000
            self.writeByte(((length >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((length >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((length >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((length & 0xFF).to_bytes(1, sys.byteorder))
        else:
            self.writeByte((0xF0).to_bytes(1, sys.byteorder))
            self.writeByte(((length >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((length >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((length >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((length & 0xFF).to_bytes(1, sys.byteorder))

    def readLen(self):
        c = ord(self.readStr(1))
        if (c & 0x80) == 0x00:
            pass
        elif (c & 0xC0) == 0x80:
            c &= ~0xC0
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xE0) == 0xC0:
            c &= ~0xE0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF0) == 0xE0:
            c &= ~0xF0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF8) == 0xF0:
            c = ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        return c

    def writeStr(self, str):
        n = 0
        while n < len(str):
            r = self.sk.send(bytes(str[n:], 'UTF-8'))
            if r == 0:
                raise RuntimeError("connection closed by remote end")
            n += r

    def writeByte(self, str):
        n = 0
        while n < len(str):
            r = self.sk.send(str[n:])
            if r == 0:
                raise RuntimeError("connection closed by remote end")
            n += r

    def readStr(self, length):
        ret = ''
        while len(ret) < length:
            s = self.sk.recv(length - len(ret))
            if s == '':
                raise RuntimeError("connection closed by remote end")

            ret += s.decode('UTF-8', 'replace')
        return ret
