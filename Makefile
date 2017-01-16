CFLAGS = -g -O3 -Wall

ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS += -I$(ERLANG_PATH)
CFLAGS += -Ic_src

ifneq ($(OS),Windows_NT)
	CFLAGS += -fPIC

	ifeq ($(shell uname),Darwin)
		LDFLAGS += -dynamiclib -undefined dynamic_lookup
	endif
endif

NIF_SRC= \
	src/_tea.c \
	src/memdump.c \
	src/cipher_mode_cbc.c \
	src/etea_nif.c \
	src/base64.c

LDFLAGS += -lcrypto -lssl

all: etea

etea:
	$(MIX) compile

priv/etea_nif.so: $(NIF_SRC)
	$(CC) $(CFLAGS) -o $@ $(NIF_SRC) -shared $(LDFLAGS)

clean:
	$(MIX) clean
	rm -f priv/etea.so src/*.o

.PHONY: all etea clean
