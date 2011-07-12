#!/usr/bin/env python

import sys
import glopy

if len(sys.argv) != 2:
    print "Usage: %s cert_file" % sys.argv[0]

fname = sys.argv[1]
with open(fname) as f:
    data = f.read()

c = glopy.Credential()

# First try to load assuming it contains a private key; if that fails
# try again assuming no private key.
try:
    c.load_cert_and_key(data)
except glopy.error:
    c.load_cert(data)

print "Identity:  ", c.get_identity()
print "Subject:   ", c.get_subject()
print "Issuer:    ", c.get_issuer()
print "Lifetime:  ", c.get_lifetime()
print "Not Before:", c.get_not_before()
print "Not After: ", c.get_not_after()
print "Key Size:  ", c.get_key_size()
print "Has Priv K:", c.has_private_key()
print "Chain Len: ", c.get_chain_length()

print "Validate:    ",
try:
    c.validate()
except glopy.error as e:
    print "FAILED -", e
else:
    print "OK"

print "Check Issuer: ",
try:
    c.check_cert_issuer()
except glopy.error as e:
    print "FAILED -", e
else:
    print "OK"

print "Check Private Key: ",
try:
    c.check_private_key()
except glopy.error as e:
    print "FAILED -", e
else:
    print "OK"
