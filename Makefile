# Makefile for jdebug
CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = jdebug
SRC = src/jdebug.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
