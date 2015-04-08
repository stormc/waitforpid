SOURCE=waitforpid.c
EXECUTABLE=$(SOURCE:.c=)

DESTDIR =
PREFIX  = /usr/local

_CFLAGS = $(CFLAGS) -std=c99 -Wall -Wextra -Winline -Wpedantic -lcap

.DEFAULT_GOAL := ${EXECUTABLE}

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCE)
	@$(CC) $(_CFLAGS) $< -o $@

install: $(EXECUTABLE)
	@type setcap >/dev/null 2>&1 || { echo "Please install libcap"; exit 1; }
	install -D --group=root --owner=root --mode=0755 --strip $(EXECUTABLE) $(DESTDIR)/$(PREFIX)/sbin/$(EXECUTABLE)
	setcap cap_net_admin+p $(DESTDIR)/$(PREFIX)/sbin/$(EXECUTABLE)

.PHONY: clean
clean:
	@rm -f $(EXECUTABLE)
