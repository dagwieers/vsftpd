/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * ascii.c
 *
 * Routines to handle ASCII mode tranfers. Yuk.
 */

unsigned int
vsf_ascii_ascii_to_bin(const char* p_in, char* p_out, unsigned int in_len)
{
  /* Task: translate all \r\n into plain \n
   * For simplicity, I'm cheating and just ripping out all \r. If someone
   * complains about it breaking something, it'll get fixed.
   */
  unsigned int indexx = 0;
  unsigned int written = 0;
  while (indexx < in_len)
  {
    char the_char = p_in[indexx];
    if (the_char != '\r')
    {
      *p_out++ = the_char;
      written++;
    }
    indexx++;
  }
  return written;
}

unsigned int
vsf_ascii_bin_to_ascii(const char* p_in, char* p_out, unsigned int in_len)
{
  /* Task: translate all \n into \r\n. Note that \r\n becomes \r\r\n. That's
   * what wu-ftpd does, and it's easier :-)
   */
  unsigned int indexx = 0;
  unsigned int written = 0;
  while (indexx < in_len)
  {
    char the_char = p_in[indexx];
    if (the_char == '\n')
    {
      *p_out++ = '\r';
      written++;
    }
    *p_out++ = the_char;
    written++;
    indexx++;
  }
  return written;
}

