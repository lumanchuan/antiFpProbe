/* -*- P4_16 -*- */
#ifndef ENB_P0F
#define ENB_P0F 0
#endif
#ifndef ENB_NMAP
#define ENB_NMAP 1
#endif
#define ENB_XPROBE 0


#if ENB_P0F
#include "p0f_tofino.p4"

#elif ENB_NMAP
#include "nmap_tofino.p4"

#elif ENB_XPROBE
#include "xprobe_tofino.p4"


#endif
