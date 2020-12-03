SRCS:=$(shell find . -name "*.S")
OBJS:=$(SRCS:.S=.o)
TARGETS:=$(SRCS:.S=.bin)
GENERATED_TARGETS=sf.gen.bin cf.gen.bin of.gen.bin above.gen.bin greater_eq.gen.bin greater.gen.bin alu.gen.bin
GENERATED_SRCS=$(GENERATED_TARGETS:.bin=.S)
.SECONDARY:

# Tell LD to account for a max page size of 64k. This lets us easily test
# our binaries on ppc64le 64k hosts. Real binaries will need to be run on a
# 4k host.
#
# --no-relax prevents the linker from optimizing away things like RIP-relative
#  addressing which we want to explicitly keep for testing
LDFLAGS:=-z max-page-size=65536 --no-relax

all: $(TARGETS) $(GENERATED_TARGETS)

%.gen.S: ./gentest.py
	./gentest.py $(@:.gen.S=) $@

%.bin: %.o
	x86_64-unknown-linux-gnu-ld $(LDFLAGS) $< -o $@

%.o: %.S
	x86_64-unknown-linux-gnu-as $< -o $@

clean:
	rm -rf $(TARGETS)
	rm -rf *.o
	rm -rf $(GENERATED_TARGETS)
	rm -rf $(GENERATED_SRCS)
