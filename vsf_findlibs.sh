#!/bin/sh
# Cheesy hacky location of additional link libraries.

# Optimizations for specific platforms, to avoid unneccessary libraries
if [ -r /etc/redhat-release ]; then
  grep '7\.' /etc/redhat-release >/dev/null && echo "-lpam" && exit
  grep '6\.' /etc/redhat-release >/dev/null && echo "-lpam -ldl" && exit
fi

locate_library() { [ ! "$1*" = "`echo $1*`" ]; }

# Look for PAM
locate_library /lib/libpam.so && echo "-lpam";

# Look for PAM in alternate location (FreeBSD)
locate_library /usr/lib/libpam.so && echo "-lpam";

# Look for the crypt library
# XXX - adds a link library even if it's not needed
locate_library /lib/libcrypt.so && echo "-lcrypt"

# Look for the crypt library (FreeBSD)
locate_library /usr/lib/libcrypt.so && echo "-lcrypt"

# Look for the dynamic linker library. Needed by older RedHat when
# you link in PAM
locate_library /lib/libdl.so && echo "-ldl";

# Look for libsocket. Solaris needs this.
locate_library /lib/libsocket.so && echo "-lsocket";

# Look for libnsl. Solaris needs this.
locate_library /lib/libnsl.so && echo "-lnsl";

# Look for libutil. Older FreeBSD need this for setproctitle().
locate_library /usr/lib/libutil.so && echo "-lutil";

# HP-UX ends shared libraries with .sl
locate_library /usr/lib/libpam.sl && echo "-lpam";

# For older HP-UX...
locate_library /usr/lib/libsec.sl && echo "-lsec";

