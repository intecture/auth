UNAME_S := $(shell uname -s)
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
	mkdir -p $(PREFIX)/etc/intecture/users
	sed 's~<CFGPATH>~$(PREFIX)/etc/intecture~' resources/auth.json > $(PREFIX)/etc/intecture/auth.json
	chmod 0644 $(PREFIX)/etc/intecture/auth.json
	install -m 0755 target/$(TARGET)/inauth_server $(PREFIX)/bin/
	install -m 0755 target/$(TARGET)/inauth_cli $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/bin/inauth_server
	rm -f $(PREFIX)/bin/inauth_cli
	rm -f $(PREFIX)/etc/intecture/auth.json
	if [ ! "$(ls -A /$(PREFIX)/etc/intecture)" ]; then\
		rmdir $(PREFIX)/etc/intecture; \\
	fi

test:
ifeq ($(TARGET), release)
	$(CARGO) test --release
else
	$(CARGO) test
endif

clean:
	$(CARGO) clean
