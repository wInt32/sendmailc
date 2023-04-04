SOURCES=src/cJSON.c src/sendmail.c
OBJ=obj/cJSON.o obj/sendmail.o
LIB=lib/libsendmail.a
CFLAGS:=-Iinclude -c $(CFLAGS)
CC?=gcc
AR?=ar
RM?=rm

.PHONY: clean

all: $(LIB)

obj/%.o : src/%.c
	$(CC) $< -o $@ $(CFLAGS)


$(LIB): $(OBJ)
	$(RM) $@
	$(AR) cq $@ $^

clean:
	$(RM) $(OBJ) $(LIB)