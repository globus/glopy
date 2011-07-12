from distutils.core import setup, Extension

import os
import sys

# Configuration
FLAVOR = "gcc64dbg"
SYSTEM_SSL=True

globus_location = os.getenv("GLOBUS_LOCATION")
if globus_location is None:
    print "Please set GLOBUS_LOCATION"
    sys.exit(1)

source_files = ["glopymodule.c", "credentialtype.c", "globus_gsi_cred_patch.c"]
source_paths = map(lambda s: "src/" + s, source_files)

def get_globus_libs(*args):
    libs = []
    for arg in args:
        for subarg in arg.split():
            libs.append("globus_%s_%s" % (subarg, FLAVOR))
    return libs

globus_libs = get_globus_libs("common", "oldgaa",
                              "openssl", "openssl_error",
                              "proxy_ssl",
                              "gsi_callback", "gsi_cert_utils",
                              "gsi_credential", "gsi_sysconfig")

ssl_libs = "ssl crypto".split()
if not SYSTEM_SSL:
    ssl_libs = map(lambda x: x + "_" + falvor, ssl_libs)

glopymodule = Extension("glopy", source_paths,
     include_dirs=[os.path.join(globus_location,
                                "include", FLAVOR)],
     library_dirs=[os.path.join(globus_location, "lib")],
     libraries=globus_libs
               + ["dl", "ltdl_" + FLAVOR]
               + ssl_libs,
     depends=["glopymodule.h", "credentialtype.h"],
     extra_compile_args=["-g", "-Wno-strict-prototypes"])

setup(name = "glopy",
      version = "0.1",
      description="Python library wrapping Globus Toolkit",
      author="Bryce Allen",
      url="http://www.globus.org",
      author_email="ballen@ci.uchicago.edu",
      ext_modules = [glopymodule])
