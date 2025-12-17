CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3
LIBS = -lelf -lcapstone

SRC_FILES = disassembler.c
OBJ_FILES = $(SRC_FILES:.c=.o)
INCLUDE_DIR = .

TARGET = disas.out

$(TARGET): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) 

%.o: %.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

debug: CFLAGS += -ggdb
debug: clean $(TARGET)

clean:
	rm -f $(OBJ_FILES) $(TARGET)
