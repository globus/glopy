#!/usr/bin/env python
"""
Test the gt credential module by repeatedly loading credentials, re
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

    def run(self):
        c = self.c
        #c = glopy.Credential()
        for i in xrange(self.trials):
            for cred in self.credentials:
                if cred.find("proxy") != -1:
                    c.load_proxy_file(cred)
                elif cred.find("key") != -1:
                    # not a valid cert, make sure we get an error
                    try:
                        c.load_cert_file(cred)
                    except glopy.error as e:
                        pass
                    else:
                        print "ERROR: loaded non cert w/o exception"
                        return
                else:
                    c.load_cert_file(cred)
                try:
                    c.verify_chain()
                except glopy.error as e:
                    print "ERROR: ", str(e)
                    return

if __name__ == '__main__':
    threads = int(sys.argv[1])
    trials = int(sys.argv[2])
    creds = sys.argv[3:]

    ts = []
    for i in xrange(threads):
        t = LoadCreds(trials, *creds)
        ts.append(t)
        t.start()

    for t in ts:
        t.join()
