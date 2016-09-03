TARGET = release
PREFIX = /usr/local

all:
ifeq ($(TARGET), release)
	cargo build --release
else
	cargo build
endif

install:
	mkdir -p $(PREFIX)/etc/intecture/certs
	sed 's~<CFGPATH>~$(PREFIX)/etc/intecture~' resources/auth.json > $(PREFIX)/etc/intecture/auth.json
	chmod 0644 $(PREFIX)/etc/intecture/auth.json
	install -m 0755 target/$(TARGET)/inauth $(PREFIX)/bin/
	install -m 0755 target/$(TARGET)/inauth_cli $(PREFIX)/bin/
	if [ -f /etc/rc.conf ]; then \
		install -m 555 resources/init/freebsd /etc/rc.d/inauth; \
	elif stat --format=%N /proc/1/exe|grep -qs systemd ; then \
		if [ -d /usr/lib/systemd/system ]; then \
			install -m 644 resources/init/systemd /usr/lib/systemd/system/inauth.service; \
		elif [ -d /lib/systemd/system ]; then \
			install -m 644 resources/init/systemd /lib/systemd/system/inauth.service; \
		fi; \
	elif [ -f /etc/redhat-release ]; then \
		install -m 755 resources/init/redhat /etc/init.d/inauth; \
	elif [ -f /etc/debian_version ]; then \
		install -m 755 resources/init/debian /etc/init.d/inauth; \
	fi;

uninstall:
	rm -f $(PREFIX)/bin/inauth
	rm -f $(PREFIX)/bin/inauth_cli
	rm -f $(PREFIX)/etc/intecture/auth.json
	rmdir --ignore-fail-on-non-empty $(PREFIX)/etc/intecture
	rm -f /lib/systemd/system/inauth.service
	rm -f /usr/lib/systemd/system/inauth.service
	rm -f /etc/init.d/inauth
	rm -f /etc/rc.d/inauth

test:
ifeq ($(TARGET), release)
	cargo test --release
else
	cargo test
endif

clean:
	cargo clean
