retrec
======

retrec is a retargetable dynamic recompiler for Linux userspace binaries that
currently targets x86\_64 binaries on ppc64le (ISA 3.0B+) hosts. Support for other
host ISAs (riscv64, aarch64) is planned.

Unlike other retargetable userspace binary translators like [qemu-user](https://www.qemu.org/docs/master/user/main.html),
retrec trades simplicity and portability for performance. While QEMU's code generator (TCG)
is designed to be easy to port, retrec's code generation is designed to enable the most efficient
translation possible, at the cost of requiring more complex architecture-specific backends.

An example of the design differences between the two can be seen in the intermediate representations
(IR) used by each. All QEMU target ISAs are lowered to a lowest-common-denominator IR (TCGops),
whereas retrec's IR (llir) aims to provide a lossless 1:1 representation for any source ISA
instruction. This means that while llir codegen backends must necessarily be more complex
than TCG backends, they are also potentially able to emit more optimized code since no
lossy conversions to/from representations have occurred.

In the future, retrec also aims to provide support for invoking host library routines from translated
processes, much like the [box86](https://github.com/ptitSeb/box86) project. Unlike box86, though,
retrec only targets 64-bit ISAs and has a retargetable code generator instead of an ARM-only one.

Status
------
retrec is under heavy development and currently only implements a small fraction of the X86\_64
ISA and only supports ppc64le (ISA 3.0B+) hosts. Currently only very basic statically-linked C programs run.

Roadmap:

- [x] Basic ELF loader
- [x] Support for basic x86\_64 instructions (integer ALU, branch, etc.) (in progress)
- [x] ppc64le codegen backend (in progress)
- [ ] Support for more x86\_64 instructions (FPU, misc.) (in progress)
- [ ] Support for more syscalls
- [ ] Thread support
- [ ] Dynamically linked binary support
- [ ] SIMD (SSE, AVX)
- [ ] aarch64 codegen backend
- [ ] riscv64 codegen backend
- [ ] JIT cache
- [ ] Optimization passes
- [ ] Support for calling into host libraries
- [ ] Potential LLVM integration for translating hot routines?
- [ ] ???

If you would like to contribute to retrec's development, don't hesitate reach out!

Building
--------
retrec is still in very early stages, so building is currently only useful for those interested
in contributing to its development. The only dependencies are cmake, libelf, and a C++17 compiler.

```
$ mkdir build && cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Debug
$ make
```

Afterwards, you can run the test suite. Note that this requires an `x86_64-unknown-linux-gnu` toolchain.
```
$ cd ../test
$ make
$ ./runtests.py ../build/src/retrec
```

License
-------
retrec is licensed under the GNU Lesser General Public License (LGPL), version 3 or later. See LICENSE.md.
