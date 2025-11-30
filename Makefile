# Define the compiler and compiler flags
CC = gcc
CFLAGS = -Wall -Werror -O3
LIBS = -lelf -lcapstone

# Define the source files and the object files
SRC_FILES = disassembler.c
OBJ_FILES = $(SRC_FILES:.c=.o)

# Define the target executable
TARGET = a.out

# Build the executable
$(TARGET): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) 

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Debug target for use with GDB
debug: CFLAGS += -ggdb
debug: clean $(TARGET)

# Clean the project (remove object files and the executable)
clean:
	rm -f $(OBJ_FILES) $(TARGET)
