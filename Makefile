# Makefile for systems with GNU tools
CC 	=	gcc
INSTALL	=	install
IFLAGS  = -idirafter dummyinc
CFLAGS	=	-O2 -Wall -W -Wshadow #-pedantic -Werror -Wconversion

LIBS	=	`./vsf_findlibs.sh`
LINK	=	-s

OBJS	=	main.o utility.o prelogin.o ftpcmdio.o postlogin.o privsock.o \
		tunables.o ftpdataio.o secbuf.o ls.o \
		postprivparent.o logging.o str.o netstr.o sysstr.o strlist.o \
    dirchange.o filestr.o parseconf.o secutil.o \
    ascii.o oneprocess.o twoprocess.o privops.o \
    sysutil.o sysdeputil.o

.c.o:
	$(CC) -c $*.c $(CFLAGS) $(IFLAGS)

vsftpd: $(OBJS) 
	$(CC) -o vsftpd $(OBJS) $(LINK) $(LIBS)

install:
	$(INSTALL) -m 755 vsftpd /usr/sbin/vsftpd
	if [ -x /etc/xinetd.d ]; then \
		$(INSTALL) -m 644 xinetd.d/vsftpd /etc/xinetd.d/vsftpd; fi

clean:
	rm -f *.o *.swp vsftpd

