#!/bin/sh
# Cheesy hacky location of additional link libraries.

locate_library() { [ ! "$1*" = "`echo $1*`" ]; }

# Optimizations for specific platforms, to avoid unneccessary libraries
# Check for Mandrake first, because it also pretends to be RedHat!!
if [ -r /etc/mandrake-release ]; then
  if [ -r /usr/include/security/pam_appl.h ]; then
    # Yes, Mandrake's PAM installation is broken
    echo "/lib/libpam.so.0";
  else
    echo "-lcrypt";
  fi
  if [ -r /usr/include/sys/capability.h ]; then
    echo "-lcap";
  fi
  exit
elif [ -r /etc/redhat-release ]; then
  if [ -r /usr/include/security/pam_appl.h ]; then
    echo "-lpam";
    grep '6\.' /etc/redhat-release >/dev/null && echo "-ldl"
    grep '5\.' /etc/redhat-release >/dev/null && echo "-ldl"
  else
    echo "-lcrypt";
  fi
  # Look for libcap, seems to be an optional RH7.2 thing (and may have been
  # hand installed anyway)
  if [ -r /usr/include/sys/capability.h ]; then
    echo "-lcap";
  fi
  exit
fi

# Look for PAM (done weirdly due to distribution bugs (e.g. Debian)
locate_library /lib/libpam.so.0 && echo "/lib/libpam.so.0";
locate_library /usr/lib/libpam.so && echo "-lpam";

# Look for the crypt library
# XXX - adds a link library even if it's not needed
locate_library /lib/libcrypt.so && echo "-lcrypt"
locate_library /usr/lib/libcrypt.so && echo "-lcrypt"

# Look for the dynamic linker library. Needed by older RedHat when
# you link in PAM
locate_library /lib/libdl.so && echo "-ldl";

# Look for libsocket. Solaris needs this.
locate_library /lib/libsocket.so && echo "-lsocket";

# Look for libnsl. Solaris needs this.
locate_library /lib/libnsl.so && echo "-lnsl";

# Look for libresolv. Solaris needs this.
locate_library /lib/libresolv.so && echo "-lresolv";

# Look for libutil. Older FreeBSD need this for setproctitle().
locate_library /usr/lib/libutil.so && echo "-lutil";

# HP-UX ends shared libraries with .sl
locate_library /usr/lib/libpam.sl && echo "-lpam";

# For older HP-UX...
locate_library /usr/lib/libsec.sl && echo "-lsec";

# AIX ends shared libraries with .a
locate_library /usr/lib/libpam.a && echo "-lpam";

# Look for libcap (capabilities)
locate_library /lib/libcap.so /usr/lib/libcap.so && echo "-lcap";

# Solaris needs this for nanosleep()..
locate_library /lib/libposix4.so /usr/lib/libposix4.so && echo "-lposix4";

# Tru64 (nanosleep)
locate_library /usr/shlib/librt.so && echo "-lrt";

