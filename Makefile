CARGO := $(shell which cargo)
TARGET = release
PREFIX = /usr/local

all:
ifeq ($(TARGET), release)
	$(CARGO) build --release
else
	$(CARGO) build
endif

install:
	mkdir -p $(PREFIX)/etc/intecture/certs
	sed 's~<CFGPATH>~$(PREFIX)/etc/intecture~' resources/auth.json > $(PREFIX)/etc/intecture/auth.json
	chmod 0644 $(PREFIX)/etc/intecture/auth.json
	install -m 0755 target/$(TARGET)/inauth $(PREFIX)/bin/
	install -m 0755 target/$(TARGET)/inauth_cli $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/bin/inauth
	rm -f $(PREFIX)/bin/inauth_cli
	rm -f $(PREFIX)/etc/intecture/auth.json
	rmdir --ignore-fail-on-non-empty $(PREFIX)/etc/intecture

test:
ifeq ($(TARGET), release)
	$(CARGO) test --release
else
	$(CARGO) test
endif

clean:
	$(CARGO) clean
