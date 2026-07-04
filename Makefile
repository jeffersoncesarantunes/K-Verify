CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2 -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS = -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie
TARGET = kverify
TEST_TARGET = test_kverify
OBJ_DIR = build/obj
REPORT_DIR = reports
PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man/man1

SRCS = $(shell find src -name "*.c")
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)
TEST_SRCS = $(filter-out src/main.c, $(SRCS))
TEST_OBJS = $(TEST_SRCS:src/%.c=$(OBJ_DIR)/%.o)
TEST_RUNNER = $(OBJ_DIR)/tests/test_utils.o

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(REPORT_DIR)
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@strip $(TARGET)
	@echo "✅ Build successful."

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/tests/%.o: tests/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_OBJS) $(TEST_RUNNER)
	@$(CC) $(TEST_OBJS) $(TEST_RUNNER) -o $(TEST_TARGET) $(LDFLAGS)
	@echo "🧪 Running test suite..."
	@./$(TEST_TARGET)
	@echo "✅ Tests complete."

install: $(TARGET) install-man
	@install -m 755 -d $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	@echo "  📦 Installed $(TARGET) to $(BINDIR)"

install-man:
	@install -m 755 -d $(MANDIR)
	@install -m 644 man/kverify.1 $(MANDIR)/kverify.1
	@echo "  📄 Installed man page to $(MANDIR)"

uninstall:
	@rm -f $(BINDIR)/$(TARGET)
	@rm -f $(MANDIR)/kverify.1
	@-rmdir $(MANDIR) 2>/dev/null; true
	@echo "  🗑 Removed $(TARGET)"

clean:
	@echo "🧹 Clean."
	@rm -rf build/
	@rm -f $(TARGET)
	@rm -f $(TEST_TARGET)

purge: clean
	@rm -rf $(REPORT_DIR)
