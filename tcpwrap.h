#ifndef VSF_TCPWRAP_H
#define VSF_TCPWRAP_H

struct vsf_sysutil_sockaddr;

int vsf_tcp_wrapper_ok(const struct vsf_sysutil_sockaddr* p_addr);

#endif /* VSF_TCPWRAP_H */

