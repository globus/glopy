#!/usr/bin/env python

import sys
import gt

if len(sys.argv) != 2:
    print "Usage: %s cert_file" % sys.argv[0]

fname = sys.argv[1]
with open(fname) as f:
    data = f.read()

c = gt.Credential(data)

print "Subject: ", c.get_subject()
print "Issuer:  ", c.get_issuer()
print "Lifetime:", c.get_lifetime()
print "Goodtill:", c.get_goodtill()

print "Verify Chain:",
try:
    c.verify_chain()
except gt.error as e:
    print "FAILED -", e
else:
    print "OK"
