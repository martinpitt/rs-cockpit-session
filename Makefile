# FIXME
PORT = 2201
HOST = root@127.0.0.2
SSHOPTS = -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o CheckHostIP=no -i bots/machine/identity
SSH = ssh $(SSHOPTS) -p $(PORT) $(HOST)
SCP = scp $(SSHOPTS) -P $(PORT)

rs-cockpit-session: Cargo.toml src/main.rs
	cargo build
	ln -sfn target/debug/rs-cockpit-session

bots:
	git clone --depth=1 https://github.com/cockpit-project/bots

start-vm: bots
	bots/vm-run -s cockpit.socket $${TEST_OS:-fedora-34}

test-cockpit: bots
	$(SSH) -tt curl -u admin:foobar http://localhost:9090/cockpit/login

test-rs: bots rs-cockpit-session
	@$(SCP) rs-cockpit-session $(HOST):/usr/libexec/
	@$(SSH) 'set -e; F=/usr/libexec/rs-cockpit-session; \
		 chgrp cockpit-wsinstance $$F; chmod 4750 $$F; \
		 chcon -u system_u -t cockpit_session_exec_t $$F; \
		 mount -o bind $$F /usr/libexec/cockpit-session; \
		 journalctl --lines=0 -t cockpit-tls -t cockpit-ws -t cockpit-session -ocat -f & \
		 JOURNAL_PID=$$!; \
		 trap "sleep 2; umount /usr/libexec/cockpit-session;  kill $$JOURNAL_PID" EXIT INT QUIT PIPE; \
		 curl -IsS -u admin:foobar http://localhost:9090/cockpit/login'

.PHONY: build start-vm journal test-cockpit test-rs
