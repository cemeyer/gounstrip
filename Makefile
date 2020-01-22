SRCS+=		gounstrip.c
CFLAGS?=	-O2 -pipe -g -Wall
CFLAGS+=	-Icommon
PROG=		gounstrip
LIBADD=		elf

.PATH:		libelftc
SRCS+=		elftc_string_table.c
SRCS+=		libelftc_hash.c

MK_MAN=		no

.include <bsd.prog.mk>
