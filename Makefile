CC ?= /usr/bin/cc
RM = /bin/rm

SRCDIR = src/
INCLUDEDIR = include/
BUILDDIR = build/
KYBERDIR = kyber/ref/

KYBERSOURCES = \
	$(KYBERDIR)kex.c \
	$(KYBERDIR)kem.c \
	$(KYBERDIR)indcpa.c \
	$(KYBERDIR)polyvec.c \
	$(KYBERDIR)poly.c \
	$(KYBERDIR)ntt.c \
	$(KYBERDIR)cbd.c \
	$(KYBERDIR)reduce.c \
	$(KYBERDIR)verify.c \
	$(KYBERDIR)randombytes.c \
	$(KYBERDIR)fips202.c \
	$(KYBERDIR)symmetric-shake.c

SOURCES = \
	$(KYBERSOURCES) \
	$(wildcard $(SRCDIR)*.cpp)

base64-11.o: $(SRCDIR)base64.cpp $(INCLUDEDIR)base64.h
	$(CC) -c $(SRCDIR)base64.cpp -o libbase64.o

main: $(SOURCES)
	mkdir -p $(BUILDDIR)
	$(CC) -lstdc++ -I$(INCLUDEDIR) -I$(KYBERDIR) -DKYBER_K=2 $(SOURCES) -o $(BUILDDIR)main

clean:
	-$(RM) -rf $(BUILDDIR)main
