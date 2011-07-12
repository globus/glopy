#!/usr/bin/env python
"""
Test the glopy credential module by repeatedly loading credentials, re
using the same handle over and over, and check for memory leaks.
"""
import sys
import os
from threading import Thread
import glopy

TEST_DIR = os.path.abspath(__file__)
TMP_DIR = os.path.join(TEST_DIR, "tmp")

class LoadCreds(Thread):
    def __init__(self, trials, *credentials):
        Thread.__init__(self)
        self.trials = trials
        self.credentials = credentials
        self.c = glopy.Credential()
        self.count = dict(total=0,
                          bad_chain=0,
                          bad_private_key=0,
                          bad_cert=0)

    def run(self):
        c = self.c

        for i in xrange(self.trials):
            total = 0
            bad_chain = 0
            bad_cert = 0
            bad_private_key = 0

            for cred in self.credentials:
                if cred.find("-key") != -1:
                    # not a valid cert, make sure we get an error
                    try:
                        c.load_cert_file(cred)
                    except glopy.error as e:
                        pass
                    else:
                        print "ERROR: loaded non cert w/o exception: %s" \
                              % cred
                        return
                    try:
                        c.load_cert_and_key_file(cred)
                    except glopy.error as e:
                        pass
                    else:
                        print "ERROR: loaded non proxy w/o exception: %s" \
                              % cred
                        return
                else:
                    try:
                        c.load_cert_and_key_file(cred)
                    except glopy.error as e:
                        c.load_cert_file(cred)
                    total += 1

                    c.get_not_before()
                    c.get_not_after()
                    c.get_subject()
                    c.get_identity()
                    c.get_lifetime()
                    c.get_key_size()
                    c.get_chain_length()
                    c.has_private_key()

                    try:
                        c.validate()
                    except glopy.error as e:
                        bad_chain += 1
                    try:
                        c.check_cert_issuer()
                    except glopy.error as e:
                        bad_cert += 1
                    try:
                        c.check_private_key()
                    except glopy.error as e:
                        bad_private_key += 1


            if i == 0:
                self.count["total"] = total
                self.count["bad_chain"] = bad_chain
                self.count["bad_cert"] = bad_cert
                self.count["bad_private_key"] = bad_private_key
            else:
                if self.count["total"] != total:
                    print "ERROR: total mismatch %d != %d" \
                          % (total, self.count["total"])
                if self.count["bad_chain"] != bad_chain:
                    print "ERROR: bad_chain mismatch %d != %d" \
                          % (bad_chain, self.count["bad_chain"])
                if self.count["bad_cert"] != bad_cert:
                    print "ERROR: bad_cert mismatch %d != %d" \
                          % (bad_cert, self.count["bad_cert"])
                if self.count["bad_private_key"] != bad_private_key:
                    print "ERROR: bad_private_key mismatch %d != %d" \
                          % (bad_private_key, self.count["bad_private_key"])

if __name__ == '__main__':
    threads = int(sys.argv[1])
    trials = int(sys.argv[2])
    creds = sys.argv[3:]

    ts = []
    for i in xrange(threads):
        t = LoadCreds(trials, *creds)
        ts.append(t)
        t.start()

    total = None
    bad_chain = None
    bad_cert = None
    bad_private_key = None

    for t in ts:
        t.join()
        if total and t.count["total"] != total:
            print "ERROR: total mismatch %d != %d" \
                  % (total, t.count["total"])
        if bad_chain and t.count["bad_chain"] != bad_chain:
            print "ERROR: bad_chain mismatch %d != %d" \
                  % (bad_chain, t.count["bad_chain"])
        if bad_cert and t.count["bad_chain"] != bad_chain:
            print "ERROR: bad_cert mismatch %d != %d" \
                  % (bad_cert, t.count["bad_chain"])
        if bad_private_key and t.count["bad_private_key"] != bad_private_key:
            print "ERROR: bad_private_key mismatch %d != %d" \
                  % (bad_private_key, t.count["bad_private_key"])
        total = t.count["total"]
        bad_chain = t.count["bad_chain"]
        bad_cert = t.count["bad_cert"]
        bad_private_key = t.count["bad_private_key"]

    print "total = %d" % total
    print "bad_chain = %d" % bad_chain
    print "bad_cert = %d" % bad_cert
    print "bad_private_key = %d" % bad_private_key
