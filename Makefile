CC      ?= clang
PODMAN  ?= podman

VERSION = v0.1.0
BINDIR  = bin
INCDIR  = include
BINARY  = legion
CFLAGS  = -g -std=c2x -Wall -Wextra -fpic \
          -I/usr/local/include \
          -Dbin_name=$(BINARY) \
          -D$(BINARY)_version=$(VERSION) \
		  -Dgit_sha=$(shell git rev-parse HEAD)
LDFLAGS = -L/usr/local/lib \
          -lrattler \
          -lpapago \
          -lmaple \
          -lsqlite3 \
          -lssl \
          -lcrypto \
          -ljansson \
          -luuid \
          -llogger \
          -lpthread \
		  -lcurl
PREFIX = /usr/local

MACOS_MANPAGE_LOC = /usr/share/man
LINUX_MANPAGE_LOC = /usr/share/man/man1

$(BINDIR)/$(BINARY): $(BINDIR) clean
	$(CC) $(CFLAGS) main.c server.c node.c pki.c db.c agent.c -o $(BINDIR)/$(BINARY) $(LDFLAGS)
	
$(BINDIR):
	mkdir -p $(BINDIR)

.PHONY: legionctl
legionctl:
	$(CC) $(CFLAGS) legionctl/main.c -o $(BINDIR)/$(BINARY)ctl $(LDFLAGS)

.PHONY: install
install: $(BINDIR)/$(BINARY)
	install $(BINDIR)/$(BINARY) $(PREFIX)/$(BINDIR)/$(BINARY)
ifeq ($(UNAME_S),Darwin)
	cp $(BINARY).1 $(MACOS_MANPAGE_LOC)/$(BINARY).1
else
	cp $(BINARY).1 $(LINUX_MANPAGE_LOC)/$(BINARY).1
endif

.PHONY: uninstall
uninstall: 
	rm -f $(PREFIX)/$(BINDIR)/$(BINARY)*
ifeq ($(UNAME_S),Darwin)
	rm -f $(MACOS_MANPAGE_LOC)/$(BINARY).1
else
	rm -f $(LINUX_MANPAGE_LOC)/$(BINARY).1
endif

.PHONY: image
image:
	$(PODMAN) build -t briandowns/$(BINARY):latest .

.PHONY: push
push:
	$(PODMAN) push briandowns/$(BINARY):latest

.PHONY: clean
clean:
	rm -f $(BINDIR)/*
