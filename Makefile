SOURCES=src/cJSON.c src/sendmail.c
OBJ=obj/cJSON.o obj/sendmail.o
LIB=lib/libsendmail.a
CFLAGS:=-Iinclude -c $(CFLAGS)
CC?=gcc
AR?=ar
CC:=$(CROSS_COMPILE)$(CC)
AR:=$(CROSS_COMPILE)$(AR)
RM?=rm
MKDIR?=mkdir

.PHONY: clean

all: $(LIB)

obj/%.o : src/%.c
	@$(MKDIR) -p obj
	$(CC) $< -o $@ $(CFLAGS)


$(LIB): $(OBJ)
	@$(MKDIR) -p lib
	$(RM) $@
	$(AR) cq $@ $^

clean:
	$(RM) $(OBJ) $(LIB)