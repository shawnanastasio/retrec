SRCS:=$(shell find . -name "*.S")
OBJS:=$(SRCS:.S=.o)
TARGETS:=$(SRCS:.S=.bin)

# Tell LD to account for a max page size of 64k. This lets us easily test
# our binaries on ppc64le 64k hosts. Real binaries will need to be run on a
# 4k host.
LDFLAGS:=-z max-page-size=65536

all: $(TARGETS)

%.bin: %.o
	x86_64-unknown-linux-gnu-ld $(LDFLAGS) $< -o $@

%.o: %.S
	x86_64-unknown-linux-gnu-as $< -o $@

clean:
	rm -rf $(TARGETS)
