#!/usr/bin/env python

import sys
import glopy

if len(sys.argv) != 2:
    print "Usage: %s cert_file" % sys.argv[0]

fname = sys.argv[1]
with open(fname) as f:
    data = f.read()

c = glopy.Credential(data)

print "Identity: ", c.get_identity()
print "Subject: ", c.get_subject()
print "Issuer:  ", c.get_issuer()
print "Lifetime:", c.get_lifetime()
print "Goodtill:", c.get_goodtill()

print "Verify Chain:",
try:
    c.verify_chain()
except glopy.error as e:
    print "FAILED -", e
else:
    print "OK"

print "Verify Cert:",
try:
    c.verify_cert()
except glopy.error as e:
    print "FAILED -", e
else:
    print "OK"
