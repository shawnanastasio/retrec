ASM_SRCS:=$(shell find . -name "*.S")
ASM_OBJS:=$(ASM_SRCS:.S=.o)
ASM_TARGETS:=$(ASM_SRCS:.S=.bin)
GENERATED_ASM_TARGETS= \
	asm/zf.gen.bin \
	asm/sf.gen.bin \
	asm/cf.gen.bin \
	asm/of.gen.bin \
	asm/above.gen.bin \
	asm/greater_eq.gen.bin \
	asm/greater.gen.bin \
	asm/alu.gen.bin \
	asm/load.gen.bin \
	asm/setcc.gen.bin \
	asm/x87loadstore.gen.bin
GENERATED_ASM_SRCS=$(GENERATED_ASM_TARGETS:.bin=.S)

# Freestanding (no libc) C targets
FS_C_SRCS:=$(shell find . -name "*.fs.c")
FS_C_TARGETS:=$(FS_C_SRCS:.c=.bin)
FS_CFLAGS:=-static -nostdlib -nostdinc -ffreestanding -Wall -O2 -std=gnu99

# Keep intermediate objects
.SECONDARY:

# Tell LD to account for a max page size of 64k. This lets us easily test
# our binaries on ppc64le 64k hosts. Real binaries will need to be run on a
# 4k host.
#
# --no-relax prevents the linker from optimizing away things like RIP-relative
#  addressing which we want to explicitly keep for testing
LDFLAGS:=-z max-page-size=65536 --no-relax
C_LDFLAGS:=-Wl,-z,max-page-size=65536

all: $(ASM_TARGETS) $(FS_C_TARGETS) $(GENERATED_ASM_TARGETS)

%.gen.S: asm/gentest.py
	asm/gentest.py $(notdir $(@:.gen.S=)) $@

%.bin: %.o
	x86_64-unknown-linux-gnu-ld $(LDFLAGS) $< -o $@

%.o: %.S
	x86_64-unknown-linux-gnu-as $< -o $@

%.fs.bin: %.fs.c
	x86_64-unknown-linux-gnu-gcc $(C_LDFLAGS) $(FS_CFLAGS) $< -o $@

clean:
	rm -rf $(ASM_TARGETS)
	rm -rf *.o
	rm -rf $(GENERATED_ASM_TARGETS)
	rm -rf $(GENERATED_ASM_SRCS)
	rm -rf $(FS_C_TARGETS)
