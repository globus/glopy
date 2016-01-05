"""
See README.markdown for build instructions.
"""
import subprocess
from distutils.core import setup, Extension

import os
import sys

# Hack for debian wheezy, where pyconfig.h mistakenly defines HAVE_IO_H
GLOPY_IO_H_UNDEF = (os.getenv("GLOPY_IO_H_UNDEF", "FALSE").upper()
                    in ("TRUE", "T", "1", "Y", "YES"))

PACKAGES = "globus-gsi-credential globus-common libssl".split()
CFLAGS = ["-g", "-Wno-strict-prototypes"]

SOURCE_FILES = ["glopymodule.c", "credentialtype.c", "globus_gsi_cred_patch.c"]


def pkgconfig(packages, args):
    p = subprocess.Popen(["pkg-config"] + args + packages,
                         stdout=subprocess.PIPE)
    (out, err) = p.communicate()
    if err:
        raise Exception("pkgconfig failed: %s" % err)
    return out


def pkgconfig_to_extension_kw(packages):
    """
    Generate kw args for Extension, based on output of running pkg-config
    on @packages.
    """
    kw = {}
    # map prefixes in pkg-config output to the distutils kw arg name
    flag_map = {'-I': 'include_dirs', '-L': 'library_dirs', '-l': 'libraries'}
    output = pkgconfig(packages, ["--libs", "--cflags"])
    for token in output.split():
        if token[:2] in flag_map:
            kw.setdefault(flag_map.get(token[:2]), []).append(token[2:])
        else:
            kw.setdefault('extra_compile_args', []).append(token)
    return kw


kw = pkgconfig_to_extension_kw(PACKAGES)
kw.setdefault("extra_compile_args", []).extend(CFLAGS)
if GLOPY_IO_H_UNDEF:
    kw["extra_compile_args"].append("-DGLOPY_IO_H_UNDEF")
glopymodule = Extension("glopy", map(lambda s: "src/" + s, SOURCE_FILES),
                        depends=["glopymodule.h", "credentialtype.h"],
                        **kw)

setup(name = "glopy",
      version = "0.2",
      description="Python library wrapping Globus Toolkit credential library",
      author="Bryce Allen",
      url="https://github.com/globusonline/glopy",
      author_email="ballen@ci.uchicago.edu",
      ext_modules = [glopymodule],
      keywords=["globus"],
      classifiers=[
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: Apache Software License",
          "Operating System :: MacOS :: MacOS X",
          "Operating System :: POSIX",
          "Programming Language :: Python",
          "Programming Language :: C",
          "Topic :: Security :: Cryptography",
          ],
      )
