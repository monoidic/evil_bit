DEV ?= wg0
L3_OFF ?= 0

CLANG_INCLUDES := $(shell clang -v -E - < /dev/null 2>&1 \
	| sed -n '/^#include <...> search starts here:$$/,/^End of search list\.$$/ s/^ \+/-idirafter /p')
evil_bit.o: evil_bit.c
	clang -O2 -target bpf -DL3_OFF=$(L3_OFF) $(CLANG_INCLUDES) -c $< -o $@

run: evil_bit.o
	tc qdisc replace dev $(DEV) clsact
	tc filter replace dev $(DEV) egress prio 1 handle 1 bpf da obj $< sec egress

clean:
	find . -name '*.o' -delete
	tc filter del dev $(DEV) egress
