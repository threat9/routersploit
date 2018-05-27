##############################################################
# Lempel-Ziv-Stac decompression
# BitReader and RingList classes
#
# Copyright (C) 2011  Filippo Valsorda - FiloSottile
# filosottile.wiki gmail.com - www.pytux.it
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see &lt;http://www.gnu.org/licenses/&gt;.
#
##############################################################

import collections


class BitReader:
    """
    Gets a string or a iterable of chars (also mmap)
    representing bytes (ord) and permits to extract
    bits one by one like a stream
    """

    def __init__(self, data_bytes):
        self._bits = collections.deque()

        for byte in data_bytes:
            for n in range(8):
                self._bits.append(bool((byte >> (7 - n)) & 1))

    def getBit(self):
        return self._bits.popleft()

    def getBits(self, num):
        res = 0
        for i in range(num):
            res += self.getBit() << num - 1 - i
        return res

    def getByte(self):
        return self.getBits(8)

    def __len__(self):
        return len(self._bits)


class RingList:
    """
    When the list is full, for every item appended
    the older is removed
    """

    def __init__(self, length):
        self.__data__ = collections.deque()
        self.__full__ = False
        self.__max__ = length

    def append(self, x):
        if self.__full__:
            self.__data__.popleft()
        self.__data__.append(x)
        if self.size() == self.__max__:
            self.__full__ = True

    def get(self):
        return self.__data__

    def size(self):
        return len(self.__data__)

    def maxsize(self):
        return self.__max__

    def __getitem__(self, n):
        if n >= self.size():
            return None
        return self.__data__[n]


def LZSDecompress(data, window=RingList(2048)):
    """
    Gets a string or a iterable of chars (also mmap)
    representing bytes (ord) and an optional
    pre-populated dictionary; return the decompressed
    string and the final dictionary
    """
    reader = BitReader(data)
    result = ''

    while True:
        bit = reader.getBit()
        if not bit:
            char = reader.getByte()
            result += chr(char)
            window.append(char)
        else:
            bit = reader.getBit()
            if bit:
                offset = reader.getBits(7)
                if offset == 0:
                    # EOF
                    break
            else:
                offset = reader.getBits(11)

            lenField = reader.getBits(2)
            if lenField < 3:
                length = lenField + 2
            else:
                lenField <<= 2
                lenField += reader.getBits(2)
                if lenField < 15:
                    length = (lenField & 0x0f) + 5
                else:
                    lenCounter = 0
                    lenField = reader.getBits(4)
                    while lenField == 15:
                        lenField = reader.getBits(4)
                        lenCounter += 1
                    length = 15 * lenCounter + 8 + lenField
            for i in range(length):
                char = window[-offset]
                result += chr(char)
                window.append(char)

    return result, window
