# Overview #

globy is a Python library wrapping parts of the Globus Toolkit. It is
intentionally written by hand and not with SWIG, to make it easy to develop and
audit the specific functionality required by Globus Online.

glopy is pronounced *gloppy*. It is short for GLObus PYthon.

# Usage #

See [http://globusonline.github.com/glopy/](http://globusonline.github.com/glopy/) for the generated API documentation.

Currently only supports loading and verifying certificate chains and
credentials, by wrapping globus_gsi_credential. For example:

    import glopy

    c = glopy.Credential()
    c.load_cert_file("/tmp/x509up_u1000")
    print "identity =", c.get_identity()
    print "subject =", c.get_subject()
    print "goodtill =", c.get_goodtill()
    try:
        c.verify_chain()
    except glopy.error as e:
        print "Verify Failed:", str(e)
    else:
        print "Verify OK"

It works even when no private key is present (a certificate chain), and
it understands proxy certificates.

A single credential object can be re-used to load and verify many certificates
and proxies, from files and from strings, within a single thread. However it is
**NOT THREAD SAFE**, so each thread should have it's own object.

# Building #

Globus Toolkit 5.2 or 6.0 is required.

The build script uses vanilla distutils and the `python-dev` package.

For example, on debian install `python-dev`  like this:

    apt-get install python-dev

To build and install, run this (probably as root):

    python setup.py install

If using the debian packages for 5.2 or 6.0, install:

    apt-get install libglobus-gss-assist-dev libglobus-gsi-credential-dev

this list may not be complete - try installing this as well if that fails:

    apt-get install globus-gsi-cert-utils-progs globus-proxy-utils

You might also need to install:

    apt-get install libtool

Note: There are currently lots of warnings from gt header files. It would
be nice to fix these, I may be including a header twice.

If you get "fatal error: io.h: No such file or directory", set

    export GLOPY_IO_H_UNDEF=1

In particular this seems to be caused by a bug in the python2.7-minimal
package on Debian wheezy.
