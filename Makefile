# Dimitrios Koropoulis - 3967
# csd3967@csd.uoc.gr
# CS457 - Spring 2022
# Makefile

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wno-unused-parameter

SRC = src
OBJ = obj
TARGET = demo

SRC_FILES = $(wildcard $(SRC)/*.c)
OBJ_FILES = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRC_FILES))

.PHONY: all clean

all:
	@$(MAKE) --no-print-directory clean
	@mkdir $(OBJ)
	@$(MAKE) --no-print-directory $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJ) $(TARGET)

