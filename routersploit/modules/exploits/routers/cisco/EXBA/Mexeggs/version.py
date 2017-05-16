#!/usr/bin/env python

import sys


class DictionaryOfTuples:
    def __init__(self, filename, globals = None, locals = None):
        if not globals:
            globals = {}
        if not locals:
            locals = {}

        self.filename = filename


        lines = []
        f = open(filename,'r')
        for line in f.readlines():
            line = line.strip()
            if line.startswith('('):
                lines.append(line)
        f.close()


        expression = "[\n%s\n]" % "\n".join(lines)
        tuples = eval(expression, globals, locals)


        self.info = {}
        for e in tuples:
            if e[0] in self and self[e[0]] != e[1]:
                raise RuntimeError,"data mismatch -- %s has multiple values: %s and %s" % (e[0], self[e[0]], e[1])
            else:
                self[e[0]] = e[1]

    def __len__(self):
        return len(self.info)
        
    def __contains__(self, item):
        return item in self.info
        
    def __getitem__(self, key):
        return self.info[key]
      
    def __setitem__(self, key, value):
        self.info[key] = value
      
    def has_key(self, key):
        return key in self
        
    def validate(self, required, verbose = False):    
        valid = True

        for kw in required:
            if not kw in self:
                if verbose: print "Missing %s"%kw
                valid = False
            else:
                if verbose: print "Has     %-20s =" % kw, _xprint(self[kw])

        if verbose:
            if valid: 
                print "verinfo file is valid"
            else: 
                print "verinfo file is not valid"

            print '-'*40

        return valid

    def dump(self, req, opt, verbose = 0):
        out = ""

        for kw in opt:
            if kw in self:
                out += '("%s","%s"),\n' % (kw, _xprint(self[kw]))
        out += "#-"*30 + '\n'
        for kw in req:
            out += '("%s","%s"),\n' % (kw, _xprint(self[kw]))

        return out       


def _xprint(x): 
    try:    out = '0x%x'%(long(x)&0xffffffffL)
    except: out = '"%s"'%x
    return  out


if __name__ == '__main__':
    import unittest
    import version_test
    runner = unittest.TextTestRunner()
    runner.run(version_test.suite)
    
