/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * utility.c
 */

#include "utility.h"
#include "sysutil.h"
#include "defs.h"

#define DIE_DEBUG

void
die(const char* p_text)
{
#ifdef DIE_DEBUG
  bug(p_text);
#endif
  vsf_sysutil_exit(1);
}

void
bug(const char* p_text)
{
  /* Rats. Try and write the reason to the network for diagnostics */
  vsf_sysutil_activate_noblock(VSFTP_COMMAND_FD);
  (void) vsf_sysutil_write_loop(VSFTP_COMMAND_FD, "500 OOPS: ", 10);
  (void) vsf_sysutil_write_loop(VSFTP_COMMAND_FD, p_text,
                                vsf_sysutil_strlen(p_text));
  (void) vsf_sysutil_write_loop(VSFTP_COMMAND_FD, "\r\n", 2);
  vsf_sysutil_exit(1);
}

