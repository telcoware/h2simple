# Makefile for h2sim_nghttp2

LIBH2SIM=libh2sim.a


AR=ar
CC=gcc
RM=rm
CPPFLAGS=-DTLS_MODE -DEPOLL_MODE -D_REENTRANT -D_GNU_SOURCE \
          -I$(NGHTTP2_INCDIR) -I/usr/local/include
CFLAGS=-g -W -Wall -Werror
#LDFLAGS=

LIBH2SIM_HDRS=h2.h h2_priv.h
LIBH2SIM_SRCS=h2_msg.c h2_sess.c h2_io.c
LIBH2SIM_OBJS=$(LIBH2SIM_SRCS:.c=.o)


all: $(LIBH2SIM)

$(LIBH2SIM): $(LIBH2SIM_OBJS)
	$(AR) rsu $@ $?

$(LIBH@SIM): $(LIBH2SIM_HDRS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@


clean:
	$(RM) -f $(LIBH2SIM) *.o

