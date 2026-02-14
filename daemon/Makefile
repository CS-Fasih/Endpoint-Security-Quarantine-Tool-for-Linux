# ============================================================================
# Makefile — Sentinel Endpoint Security Daemon
# ============================================================================

CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -O2 -std=c11 -D_GNU_SOURCE
CFLAGS  += -I./include
LDFLAGS  = -lwebsockets -ljson-c -lpthread

SRC_DIR  = src
OBJ_DIR  = obj
SRCS     = $(wildcard $(SRC_DIR)/*.c)
OBJS     = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET   = sentinel-daemon

PREFIX   = /usr/local
SYSTEMD  = /etc/systemd/system

# ── Build ────────────────────────────────────────────────────────────────
.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "\n  ✓  Built $(TARGET) successfully.\n"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# ── Install ──────────────────────────────────────────────────────────────
install: $(TARGET)
	@echo "Installing sentinel-daemon..."
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)
	install -m 644 sentinel.service $(SYSTEMD)/sentinel.service
	systemctl daemon-reload
	@echo "\n  ✓  Installed.  Run: sudo systemctl start sentinel\n"

# ── Uninstall ────────────────────────────────────────────────────────────
uninstall:
	systemctl stop sentinel 2>/dev/null || true
	systemctl disable sentinel 2>/dev/null || true
	rm -f $(PREFIX)/bin/$(TARGET)
	rm -f $(SYSTEMD)/sentinel.service
	systemctl daemon-reload
	@echo "\n  ✓  Uninstalled.\n"

# ── Clean ────────────────────────────────────────────────────────────────
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "  ✓  Cleaned."
