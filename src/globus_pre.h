#ifndef GLOBUS_PRE_H
#define GLOBUS_PRE_H

// This is defined by Python includes and then again by globus toolkit,
// which creates warnings. Including this header before including any
// gt headers will silence the warning.
#undef IOV_MAX

// Hack for debian wheezy, where pyconfig.h mistakenly defines HAVE_IO_H
#ifdef GLOPY_IO_H_UNDEF
#undef HAVE_IO_H
#endif

#endif
