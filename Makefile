CC = gcc

CFLAGS = -Wall -Wextra -O0 -std=c99 -g

LDFLAGS = -I/usr/Include

SRCS = blhost.c

TARGET = blhost

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
