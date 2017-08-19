CFLAGS ?= -g -O2 -funroll-loops -ftree-vectorize
CFLAGS += -std=gnu99 -Wall -Wextra -pedantic
LIBS=-lm -lrt -libverbs -lhugetlbfs
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MAN1DIR=$(PREFIX)/share/man/man1

SRCS=rdma_mr_lat.c options.c
OBJS=$(SRCS:.c=.o)
BINARY=rdma_mr_lat
MANS=rdma_mr_lat.1
MANS_F=$(MANS:.1=.txt) $(MANS:.1=.pdf)
DOCS=README.md LICENSE changelog
SPEC=rdma_mr_lat.spec

PACKAGE=rdma_mr_lat
GIT_VER:=$(shell test -d .git && git describe --tags --match 'v[0-9]*' \
		--abbrev=0 | sed 's/v//')
SRC_VER:=$(shell sed -ne 's/\#define VERSION \"\(.*\)\"/\1/p' rdma_mr_lat.c)
VERSION:=$(SRC_VER)
DISTDIR=$(PACKAGE)-$(VERSION)
DISTFILES=$(SRCS) $(MANS) $(DOCS) $(SPEC) Makefile
PACKFILES=$(BINARY) $(MANS) $(MANS_F) $(DOCS)

STRIP=strip
TARGET=$(shell ${CC} -dumpmachine)

all: checkver $(BINARY)

version: checkver
	@echo ${VERSION}

checkver:
	@if test -n "$(GIT_VER)" -a "$(GIT_VER)" != "$(SRC_VER)"; then \
		echo "ERROR: Version mismatch between git and source"; \
		echo git: $(GIT_VER), src: $(SRC_VER); \
		exit 1; \
	fi

clean:
	$(RM) -f $(OBJS) $(BINARY) $(MANS_F) rdma_mr_lat.tmp

strip: $(BINARY)
	$(STRIP) $^

install: $(BINARY) $(MANS)
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 0755 $(BINARY) $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MAN1DIR)
	install -m 644 $(MANS) $(DESTDIR)$(MAN1DIR)

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

%.ps: %.1
	man -t ./$< > $@

%.pdf: %.ps
	ps2pdf $< $@

%.txt: %.1
	MANWIDTH=80 man ./$< | col -b > $@

$(BINARY): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

dist: checkver $(DISTFILES)
	tar -cz --transform='s,^,$(DISTDIR)/,S' $^ -f $(DISTDIR).tar.gz

binary-tgz: checkver $(PACKFILES)
	${STRIP} ${BINARY}
	tar -cz --transform='s,^,$(DISTDIR)/,S' -f ${PACKAGE}-${VERSION}-${TARGET}.tgz $^

binary-zip: checkver $(PACKFILES)
	${STRIP} ${BINARY}
	ln -s . $(DISTDIR)
	zip ${PACKAGE}-${VERSION}-${TARGET}.zip $(addprefix $(DISTDIR)/,$^)
	rm $(DISTDIR)

.PHONY: all version checkver clean strip test install dist binary-tgz binary-zip
