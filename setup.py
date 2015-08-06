from __future__ import print_function
"""
See README.markdown for build instructions.
"""
from distutils.core import setup, Extension

import os
import sys

# Configuration
FLAVOR = os.getenv("GLOBUS_FLAVOR", "gcc64dbg")
SYSTEM_SSL = os.getenv("GLOPY_SYSTEM_SSL", "TRUE").upper()
if SYSTEM_SSL in ("TRUE", "T", "1", "Y", "YES"):
    SYSTEM_SSL = True
else:
    SYSTEM_SSL = False

globus_location = os.getenv("GLOBUS_LOCATION")
if globus_location is None:
    print("Please set GLOBUS_LOCATION")
    sys.exit(1)

source_files = ["glopymodule.c", "credentialtype.c", "globus_gsi_cred_patch.c"]
source_paths = ["src/" + s for s in source_files]


def add_flavor(lib_name):
    if FLAVOR:
        return lib_name + "_" + FLAVOR
    else:
        return lib_name


def add_flavor_path(path):
    if FLAVOR:
        return os.path.join(path, FLAVOR)
    else:
        return path


def get_globus_libs(*args):
    libs = []
    for arg in args:
        for subarg in arg.split():
            libs.append(add_flavor("globus_%s" % subarg))
    return libs


globus_libs = get_globus_libs("common", "oldgaa", "openssl", "openssl_error",
                              "proxy_ssl", "gsi_callback", "gsi_cert_utils",
                              "gsi_credential", "gsi_sysconfig")

ssl_libs = "ssl crypto".split()
if not SYSTEM_SSL:
    ssl_libs = [add_flavor(ssl_lib) for ssl_lib in ssl_libs]

glopymodule = Extension(
    "glopy", source_paths,
    include_dirs=["/usr/include/globus", "/usr/lib/globus/include",
                  add_flavor_path(os.path.join(globus_location, "include"))],
    library_dirs=[os.path.join(globus_location, "lib")],
    libraries=globus_libs + ["dl", add_flavor("ltdl")] + ssl_libs,
    depends=["glopymodule.h", "credentialtype.h"],
    extra_compile_args=["-g", "-Wno-strict-prototypes"])

setup(name="glopy",
      version="0.1",
      description="Python library wrapping Globus Toolkit credential library",
      author="Bryce Allen",
      url="https://github.com/globusonline/glopy",
      author_email="ballen@ci.uchicago.edu",
      ext_modules=[glopymodule],
      keywords=["globus"],
      classifiers=["Development Status :: 4 - Beta",
                   "Intended Audience :: Developers",
                   "License :: OSI Approved :: Apache Software License",
                   "Operating System :: MacOS :: MacOS X",
                   "Operating System :: POSIX",
                   "Programming Language :: Python",
                   "Programming Language :: C",
                   "Topic :: Security :: Cryptography", ], )
