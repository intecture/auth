TARGET = release
PREFIX = /usr/local
SYSCONFDIR = "$(PREFIX)/etc"

all:
ifeq ($(TARGET), release)
	cargo build --release
else
	cargo build
endif

install:
	mkdir -p $(SYSCONFDIR)/intecture/certs
	sed 's~{{sysconfdir}}~$(SYSCONFDIR)~' resources/auth.json.tpl > $(SYSCONFDIR)/intecture/auth.json
	chmod 0644 $(SYSCONFDIR)/intecture/auth.json
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
	rm -f $(PREFIX)/bin/inauth \
		  $(PREFIX)/bin/inauth_cli \
	      $(SYSCONFDIR)/intecture/auth.json \
		  /lib/systemd/system/inauth.service \
		  /usr/lib/systemd/system/inauth.service \
		  /etc/init.d/inauth \
	 	  /etc/rc.d/inauth
	rmdir --ignore-fail-on-non-empty $(SYSCONFDIR)/intecture/certs
	rmdir --ignore-fail-on-non-empty $(SYSCONFDIR)/intecture

test:
ifeq ($(TARGET), release)
	cargo test --release
else
	cargo test
endif

clean:
	cargo clean
