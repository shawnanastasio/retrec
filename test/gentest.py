#!/usr/bin/env python3
# Generate shitty x86 flag tests
import sys
from collections import namedtuple

ASM_PROLOG = \
"""
.intel_syntax noprefix

.macro print str len
    mov eax, 1 # SYS_write
    mov edi, 1
    mov esi, OFFSET \str
    mov edx, OFFSET \len
    syscall
.endm

"""

ASM_EPILOG = \
"""
    mov rax, 60 # SYS_exit
    mov edi, 0
    syscall
"""

FlagTestCase = namedtuple("FlagTestCase", ["width", "reg1_str", "reg2_str", "imm1_str", "imm2_str", "insn_str", "jmp_good", "jmp_bad"])

CARRY_TESTS = [
    # SUB (cmp)
    FlagTestCase(64, "rax", "rbx", "0", "-1", "cmp", "jc", "jnc"),
    FlagTestCase(64, "rax", "rbx", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(32, "eax", "ebx", "1", "-1", "cmp", "jc", "jnc"),
    FlagTestCase(32, "eax", "ebx", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(16, "ax", "bx", "0", "-1", "cmp", "jc", "jnc"),
    FlagTestCase(16, "ax", "bx", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(8, "ah", "bh", "0", "-1", "cmp", "jc", "jnc"),
    FlagTestCase(8, "ah", "bh", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(8, "al", "bl", "0", "-1", "cmp", "jc", "jnc"),
    FlagTestCase(8, "al", "bl", "-1", "-1", "cmp", "jnc", "jc"),
    FlagTestCase(8, "al", "", "-1", "-1", "cmp", "jnc", "jc"),
]

OVERFLOW_TESTS = [
    # SUB (cmp)
    FlagTestCase(64, "rax", "", "0x7FFFFFFFFFFFFFFF", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(64, "rax", "rbx", "0x7FFFFFFFFFFFFFFF", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(64, "rax", "", "0x8000000000000000", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(64, "rax", "rbx", "0x8000000000000000", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(64, "rax", "", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(64, "rax", "rbx", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(64, "rax", "", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)
    FlagTestCase(64, "rax", "rbx", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)

    FlagTestCase(32, "eax", "", "0x7FFFFFFF", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(32, "eax", "ebx", "0x7FFFFFFF", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(32, "eax", "", "0x80000000", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(32, "eax", "ebx", "0x80000000", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(32, "eax", "", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(32, "eax", "ebx", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(32, "eax", "", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)
    FlagTestCase(32, "eax", "ebx", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)

    FlagTestCase(16, "ax", "", "0x7FFF", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(16, "ax", "bx", "0x7FFF", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(16, "ax", "", "0x8000", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(16, "ax", "bx", "0x8000", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(16, "ax", "", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(16, "ax", "bx", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(16, "ax", "", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)
    FlagTestCase(16, "ax", "bx", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)

    FlagTestCase(8, "ah", "", "0x7F", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(8, "ah", "bh", "0x7F", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(8, "ah", "", "0x80", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(8, "ah", "bh", "0x80", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(8, "ah", "", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(8, "ah", "bh", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(8, "ah", "", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)
    FlagTestCase(8, "ah", "bh", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)

    FlagTestCase(8, "al", "", "0x7F", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(8, "al", "bl", "0x7F", "-1", "cmp", "jo", "jno"), # Positive overflow (OF)
    FlagTestCase(8, "al", "", "0x80", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(8, "al", "bl", "0x80", "1", "cmp", "jo", "jno"), # Negative overflow (OF)
    FlagTestCase(8, "al", "", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(8, "al", "bl", "0", "1", "cmp", "jno", "jo"), # Positive underflow (!OF)
    FlagTestCase(8, "al", "", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)
    FlagTestCase(8, "al", "bl", "-1", "1", "cmp", "jno", "jo"), # Negative underflow (!OF)

    # ADD
    #FlagTestCase(64, "eax", "", "0x7FFFFFFF", "1", "add", "jo", "jno")
]

SUITES = {
    "CF" : CARRY_TESTS,
    "OF" : OVERFLOW_TESTS
}

def width_to_cast(width):
    return "(u" + str(width) + ")"

def generate_tests(suites, f):
    # Write prolog
    f.write(ASM_PROLOG)

    # Generate strings for all tests
    f.write(".data\n")
    n = 0
    for suite in suites:
        for test in suite:
            width_str = width_to_cast(test.width)
            f.write("    TEST_{}_STR_PASS: .ascii \"PASS: ({} {}{}, {}{}) -> {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str, test.jmp_good))
            f.write("    TEST_{}_STR_PASS_LEN = . - TEST_{}_STR_PASS\n".format(n, n))
            f.write("    TEST_{}_STR_FAIL: .ascii \"FAIL: ({} {}{}, {}{}) -> {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str, test.jmp_bad))
            f.write("    TEST_{}_STR_FAIL_LEN = . - TEST_{}_STR_FAIL\n".format(n, n))
            f.write("    TEST_{}_STR_UNREACHABLE: .ascii \"FAIL: ({} {}{}, {}{}) -> UNREACHABLE!\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str))
            f.write("    TEST_{}_STR_UNREACHABLE_LEN = . - TEST_{}_STR_UNREACHABLE\n".format(n, n))
            f.write("\n")
            n = n + 1

    f.write(".text\n")
    f.write(".global _start\n")
    f.write("_start:\n")

    # Generate tests
    n = 0
    for suite in suites:
        for test in suite:
            assert test.__class__ is FlagTestCase # TODO support other types of tests

            f.write("{}: # Test {}\n".format(n * 10, n))
            f.write("    mov {}, OFFSET {}\n".format(test.reg1_str, test.imm1_str))
            if test.reg2_str == "":
                f.write("    {} {}, OFFSET {}\n".format(test.insn_str, test.reg1_str, test.imm2_str))
            else:
                f.write("    mov {}, OFFSET {}\n".format(test.reg2_str, test.imm2_str))
                f.write("    {} {}, {}\n".format(test.insn_str, test.reg1_str, test.reg2_str))
            f.write("    {} 2f # Bad\n".format(test.jmp_bad))
            f.write("    {} 1f # Good\n".format(test.jmp_good))

            # Unreachable
            f.write("    print TEST_{}_STR_UNREACHABLE, TEST_{}_STR_UNREACHABLE_LEN\n".format(n, n))
            f.write("    jmp 3f\n")

            # Good
            f.write("1: # Test {} PASS\n".format(n))
            f.write("    print TEST_{}_STR_PASS, TEST_{}_STR_PASS_LEN\n".format(n, n))
            f.write("    jmp 3f\n")

            # Fail
            f.write("2: # Test {} FAIL\n".format(n))
            f.write("    print TEST_{}_STR_FAIL, TEST_{}_STR_FAIL_LEN\n".format(n, n))
            f.write("3:\n\n")

            n = n + 1


    # Write epilog
    f.write(ASM_EPILOG)


def main():
    if len(sys.argv) != 3:
        print("usage: {} <suite/all> outputfile".format(sys.argv[0]))
        sys.exit(1)

    suite = sys.argv[1]
    filename = sys.argv[2]

    selected = []
    if suite == "all":
        for k, v in SUITES.items():
            selected.append(v)
    else:
        selected.append(SUITES[suite.upper()])

    with open(filename, "w") as f:
        generate_tests(selected, f)
        

if __name__ == "__main__":
    main()
