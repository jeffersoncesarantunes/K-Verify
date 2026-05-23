CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2 -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS =
TARGET = kverify
OBJ_DIR = build/obj
REPORT_DIR = reports

SRCS = $(shell find src -name "*.c")
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(REPORT_DIR)
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "✔ Build successful! 🟢"

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "🧹 Cleaning project artifacts..."
	@rm -rf build/
	@rm -f $(TARGET)
	@echo "✔ Clean complete. 🟢"

purge: clean
	@echo "🧹 Purging report directories..."
	@rm -rf $(REPORT_DIR)
	@echo "✔ Purge complete. 🟢"

.PHONY: all clean purge
