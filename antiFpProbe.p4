/* -*- P4_16 -*- */
#define ENB_P0F 0
#define ENB_NMAP 1
#define ENB_XPROBE 0


#if ENB_P0F
#include "p0f_tofino.p4"
// #include "p0f_tofino_copy.p4"

#elif ENB_NMAP
#include "nmap_tofino.p4"
// #include "nmap_direct.p4"

#elif ENB_XPROBE
#include "xprobe_tofino.p4"


#endif
