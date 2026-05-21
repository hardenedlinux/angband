CC        = gcc
CFLAGS    = -O3 -march=x86-64 -mtune=generic -Wall -Wextra -fPIC -shared
LDFLAGS   = -lm -lrt

SRCS      = cache.c timer.c memory.c hammer.c tsa_probe.c exploit_verify.c hertzbleed.c
OBJS      = $(SRCS:.c=.o)
TARGET    = libsidewinder.so
HEADER    = sidewinder.h

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[+] Built $(TARGET)"

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	@echo "[*] Compiling test program..."
	$(CC) -O0 test_primitives.c -o test_primitives -L. -lsidewinder -Wl,-rpath,. -lm
	@echo "[*] Running tests..."
	LD_LIBRARY_PATH=. ./test_primitives

clean:
	rm -f $(OBJS) $(TARGET) test_primitives
