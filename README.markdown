# Overview #

globy is a Python library wrapping parts of the Globus Toolkit. It is
intentionally written by hand and not with SWIG, to make it easy to develop and
audit the specific functionality required by Globus Online.

glopy is pronounced *gloppy*; the *jalopy* pronunciation never caught on
and is now deprecated. It is short for GLObus PYthon.

# Usage #

See [http://globusonline.github.com/glopy/](http://globusonline.github.com/glopy/) for the generated API documentation.

Currently only supports loading and verifying certificate chains and
credentials, by wrapping `globus_gsi_credential`. For example:

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

# Dependencies #

glopy requires Globus Toolkit 5.2 or 6.0 and python 2.6 or 2.7.

On debian and ubuntu, using python 2.7 (recommended) as an example:

    apt-get install python2.7-dev pkg-config

If using the official GT packages (tested on ubuntu 14.04 with GT 6):

    apt-get install libglobus-gss-assist-dev libglobus-gsi-credential-dev

# Building #

To build and install using python 2.7:

    # export PKG_CONFIG_PATH=/usr/local/globus/lib/pkgconfig
    python2.7 setup.py install

Setting `PKG_CONFIG_PATH` should not be necessary if using the official
GT packages. Use sudo if doing a system wide install, or use the --user
option to install in the current user's home directory.

# Known Issues #

If you get "fatal error: io.h: No such file or directory" when building, set

    export GLOPY_IO_H_UNDEF=1

In particular this seems to be caused by a bug in the python2.7-minimal
package on Debian wheezy.

If you get the following Python exception when creating a
glopy.Credential object:

    glopy.error: globus_sysconfig: Could not find a valid trusted CA certificates directory: The trusted certificates directory could not be found in any of the following locations:
    1) env. var. X509_CERT_DIR
    2) $HOME/.globus/certificates
    3) /etc/grid-security/certificates
    4) $GLOBUS_LOCATION/share/certificates

you need to create a certificates directory at one of the suggested
locations.
