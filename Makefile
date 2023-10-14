RM?=rm
MKDIR?=mkdir
AR?=ar

TARGET?=linux

BASENAMES=cJSON sendmail
SOURCES=$(addprefix src/,$(addsuffix .c,$(BASENAMES)))
OBJS=$(addprefix obj/,$(addsuffix .o,$(BASENAMES)))

LIB=lib/libsendmailc.a
EXAMPLE_SOURCES=examples/hello.c
BIN_SUFFIX=""
EXAMPLE_BINS:=examples/bin/hello$(BIN_SUFFIX)
LDFLAGS=-Llib -lsendmailc -lcurl
CFLAGS=-Iinclude -fPIC
CC:=$(CROSS_COMPILE)$(CC)
AR:=$(CROSS_COMPILE)$(AR)

.PHONY: clean

all: lib examples

lib: $(LIB)

examples: $(LIB) $(EXAMPLE_BINS)

obj/%.o: src/%.c
	@$(MKDIR) -p obj
	$(CC) $< -o $@ -c $(CFLAGS) $(ADDITIONAL_CFLAGS)

$(LIB): $(OBJS)
	@$(MKDIR) -p lib
	$(RM) $@
	$(AR) cq $@ $^

clean:
	$(RM) $(OBJS) $(LIB) examples/bin/*

$(EXAMPLE_BINS): $(EXAMPLE_SOURCES)
	$(CC) -o $@ $< $(CFLAGS) $(ADDITIONAL_CFLAGS) $(LDFLAGS) $(ADDITIONAL_LDFLAGS)