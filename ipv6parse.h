#ifndef VSF_IPV6PARSE_H
#define VSF_IPV6PARSE_H

struct mystr;

/* Effectively doing the same sort of job as inet_pton. Since inet_pton does
 * a non-trivial amount of parsing, we'll do it ourselves for maximum security
 * and safety.
 */

const unsigned char* vsf_sysutil_parse_ipv6(const struct mystr* p_str);

#endif /* VSF_IPV6PARSE_H */

