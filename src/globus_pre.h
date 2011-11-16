#ifndef GLOBUS_PRE_H
#define GLOBUS_PRE_H
   
// This is defined by Python includes and then again by globus toolkit,
// which creates warnings. Including this header before including any
// gt headers will silence the warning.
#undef IOV_MAX
   
#endif
