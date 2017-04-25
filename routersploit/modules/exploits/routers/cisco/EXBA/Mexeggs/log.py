import argparse

import loglib

class Log(loglib.AbstractLog):
    def __init__(self, name, version):
        super(Log, self).__init__(name, version)

    def packet(self, event, data):
        return self(event, params = {'packet': ' '.join(['%02x' % ord(byte) for byte in data])})
        
