.PHONY: all clean

CC=gcc
CFLAGS=-I.
LDFLAGS=-L. -lark

all: libark.so example/alice_to_bob_covenantless

libark.so: ark_sdk_covenantless_c.go
	./build.sh

example/alice_to_bob_covenantless: example/alice_to_bob_covenantless.c libark.so ark_sdk.h
	$(CC) -o $@ example/alice_to_bob_covenantless.c $(CFLAGS) $(LDFLAGS)

runcovenantless: example/alice_to_bob_covenantless
	./example/alice_to_bob_covenantless

clean:
	rm -f libark.so libark.h example/alice_to_bob_covenantless
