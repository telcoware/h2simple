# Makefile for h2sim_nghttp2

APPS=h2cli h2svr
LIBH2SIM=h2sim/libh2sim.a


CC=gcc
RM=rm
CPPFLAGS=-DTLS_MODE -D_REENTRANT -D_GNU_SOURCE \
          -I$(NGHTTP2_INCDIR) -I/usr/local/include
CFLAGS=-O3 -g -W -Wall -Werror
LDFLAGS= -L./h2sim -L$(NGHTTP2_LIBDIR) -L/usr/local/lib \
          -lh2sim -lnghttp2 -lcrypto -lssl


all: $(LIBH2SIM) $(APPS)

$(LIBH2SIM):
	$(MAKE) -C h2sim

h2cli: h2cli.o $(LIBH2SIM)
	gcc -o $@ $? $(CFLAGS) $(LDFLAGS)

h2svr: h2svr.o $(LIBH2SIM)
	gcc -o $@ $? $(CFLAGS) $(LDFLAGS)

$(APPS): h2sim/h2.h

%.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	$(MAKE) -C h2sim clean
	$(RM) -f $(LIBH2SIM) $(APPS) *.o

