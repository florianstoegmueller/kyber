CC ?= /usr/bin/cc
RM = /bin/rm

SRCDIR = src/
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

main: $(SOURCES)
	mkdir -p $(BUILDDIR)
	$(CC) -lstdc++ -I$(KYBERDIR) -DKYBER_K=2 $(SOURCES) -o $(BUILDDIR)main

clean:
	-$(RM) -rf $(BUILDDIR)main
	-$(RM) -rf key.txt
