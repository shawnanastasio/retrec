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

def flag_test_case_genstrs(test, n, f):
    width_str = width_to_cast(test.width)
    f.write("    TEST_{}_STR_PASS: .ascii \"PASS: ({} {}{}, {}{}) -> {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str, test.jmp_good))
    f.write("    TEST_{}_STR_PASS_LEN = . - TEST_{}_STR_PASS\n".format(n, n))
    f.write("    TEST_{}_STR_FAIL: .ascii \"FAIL: ({} {}{}, {}{}) -> {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str, test.jmp_bad))
    f.write("    TEST_{}_STR_FAIL_LEN = . - TEST_{}_STR_FAIL\n".format(n, n))
    f.write("    TEST_{}_STR_UNREACHABLE: .ascii \"FAIL: ({} {}{}, {}{}) -> UNREACHABLE!\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str))
    f.write("    TEST_{}_STR_UNREACHABLE_LEN = . - TEST_{}_STR_UNREACHABLE\n".format(n, n))
    f.write("\n")

def flag_test_case_gentest(test, n, f):
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


FlagTestCase = namedtuple("FlagTestCase", ["width", "reg1_str", "reg2_str", "imm1_str", "imm2_str",
                                           "insn_str", "jmp_good", "jmp_bad", "f_genstrs", "f_gentest"],
                                          defaults=(None,None,None,None,None,None,None,None,flag_test_case_genstrs,flag_test_case_gentest))


def alu_test_case_genstrs(test, n, f):
    width_str = width_to_cast(test.width)
    f.write("    TEST_{}_STR_PASS: .ascii \"PASS: ({} {}{}, {}{}) -> {} == {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str, test.reg1_str, test.res_str))
    f.write("    TEST_{}_STR_PASS_LEN = . - TEST_{}_STR_PASS\n".format(n, n))
    f.write("    TEST_{}_STR_FAIL: .ascii \"FAIL: ({} {}{}, {}{}) -> {} != {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, width_str, test.imm2_str, test.reg1_str, test.res_str))
    f.write("    TEST_{}_STR_FAIL_LEN = . - TEST_{}_STR_FAIL\n".format(n, n))

def alu_test_case_gentest(test, n, f):
    f.write("{}: # Test {}\n".format(n * 10, n))
    if test.imm1_str:
        f.write("    mov {}, {}\n".format(test.reg1_str, test.imm1_str))
    if test.reg2_str == "":
        if test.res_reg:
            f.write("    {} {}, OFFSET {}\n".format(test.insn_str, test.res_reg, test.res_str))
            f.write("    cmp {}, {}\n".format(test.reg1_str, test.res_reg))
        else:
            f.write("    {} {}, OFFSET {}\n".format(test.insn_str, test.res_reg, test.res_str))
            f.write("    cmp {}, OFFSET {}\n".format(test.reg1_str, test.res_str))
    else:
        if test.imm2_str:
            f.write("    mov {}, OFFSET {}\n".format(test.reg2_str, test.imm2_str))
        if test.res_reg:
            f.write("    {} {}, {}\n".format(test.insn_str, test.reg1_str, test.reg2_str))
            f.write("    mov {}, OFFSET {}\n".format(test.res_reg, test.res_str))
            f.write("    cmp {}, {}\n".format(test.reg1_str, test.res_reg))
        else:
            f.write("    {} {}, {}\n".format(test.insn_str, test.reg1_str, test.reg2_str))
            f.write("    cmp {}, OFFSET {}\n".format(test.reg1_str, test.res_str))
    f.write("    je 1f\n")

    # Fail
    f.write("# Test {} FAIL\n".format(n))
    f.write("    print TEST_{}_STR_FAIL, TEST_{}_STR_FAIL_LEN\n".format(n, n))
    f.write("    jmp 2f\n")

    # Success
    f.write("1: # Test {} PASS\n".format(n))
    f.write("    print TEST_{}_STR_PASS, TEST_{}_STR_PASS_LEN\n".format(n, n))
    f.write("2:\n\n")


AluTestCase = namedtuple("AluTestCase", ["width", "insn_str", "reg1_str", "reg2_str", "imm1_str", "imm2_str",
                                         "res_str", "res_reg", "f_genstrs", "f_gentest"],
                                        defaults=(None,None,None,None,None,None,None,alu_test_case_genstrs,alu_test_case_gentest))

def get_mem_width_str(width):
    return {
        64: "qword",
        32: "dword",
        16: "word",
        8: "byte"
    }[width]

def load_test_case_genstrs(test, n, f):
    mem_width_str = get_mem_width_str(test.width)
    width_str = mem_width_str
    if test.reg1_preload_str:
        cmp_reg = test.reg1_preload_str
    else:
        cmp_reg = test.reg1_str

    f.write("    TEST_{}_STR_PASS: .ascii \"PASS: ({} {} ptr [&{}]) -> {} == {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, cmp_reg, test.res_str))
    f.write("    TEST_{}_STR_PASS_LEN = . - TEST_{}_STR_PASS\n".format(n, n))
    f.write("    TEST_{}_STR_FAIL: .ascii \"FAIL: ({} {} ptr [&{}]) -> {} != {}\\n\"\n".format(n, test.insn_str, width_str, test.imm1_str, cmp_reg, test.res_str))
    f.write("    TEST_{}_STR_FAIL_LEN = . - TEST_{}_STR_FAIL\n".format(n, n))

    f.write("    TEST_{}_IMM_STORAGE: ".format(n))
    x = int(test.imm1_str, 0)
    if mem_width_str == "qword":
        f.write(".byte 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}\n".format(x & 0xFF, (x >> 8) & 0xFF,
            (x >> 16) & 0xFF, (x >> 24) & 0xFF, (x >> 32) & 0xFF, (x >> 40) & 0xFF, (x >> 48) & 0xFF, (x >> 56) & 0xFF))
    elif mem_width_str == "dword":
        f.write(".byte 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}\n".format(x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF))
    elif mem_width_str == "word":
        f.write(".byte 0x{:x}, 0x{:x}\n".format(x & 0xFF, (x >> 8) & 0xFF))
    elif mem_width_str == "byte":
        f.write(".byte 0x{:x}\n".format(x & 0xFF))
    else:
        print("Invalid load width {}\n".format(mem_width_str))
        sys.exit(1)


def load_test_case_gentest(test, n, f):
    mem_width_str = get_mem_width_str(test.width)
    f.write("{}: # Test {}\n".format(n * 10, n))
    if test.reg1_preload_str:
        f.write("    mov {}, {}\n".format(test.reg1_preload_str, test.imm1_preload_str))
    f.write("    {} {}, {} ptr [{}]\n".format(test.insn_str, test.reg1_str, mem_width_str, "TEST_{}_IMM_STORAGE".format(n)))
    if test.reg1_preload_str:
        cmp_reg = test.reg1_preload_str
    else:
        cmp_reg = test.reg1_str

    if test.res_reg:
        f.write("    mov {}, {}\n".format(test.res_reg, test.res_str))
        f.write("    cmp {}, {}\n".format(cmp_reg, test.res_reg))
    else:
        f.write("    cmp {}, OFFSET {}\n".format(cmp_reg, test.res_str))
    f.write("    je 1f\n")

    # Fail
    f.write("# Test {} FAIL\n".format(n))
    f.write("    print TEST_{}_STR_FAIL, TEST_{}_STR_FAIL_LEN\n".format(n, n))
    f.write("    jmp 2f\n")

    # Success
    f.write("1: # Test {} PASS\n".format(n))
    f.write("    print TEST_{}_STR_PASS, TEST_{}_STR_PASS_LEN\n".format(n, n))
    f.write("2:\n\n")


LoadTestCase = namedtuple("LoadTestCase", ["width", "insn_str",
                                           "reg1_preload_str", "imm1_preload_str",
                                           "reg1_str", "imm1_str", "res_reg",
                                           "res_str", "f_genstrs", "f_gentest"],
                                          defaults=(None,None,None,None,None,None,None,load_test_case_genstrs,load_test_case_gentest))

LOAD_TESTS = [
    # Test plain loads of all widths
    LoadTestCase(64, "mov", "", "", "rax", "0xDEADBEEFCAFEBABA", "rbx", "0xDEADBEEFCAFEBABA"),
    LoadTestCase(32, "mov", "", "", "eax", "0xDEADBEEF", "ebx", "0xDEADBEEF"),
    LoadTestCase(16, "mov", "", "", "ax", "0xBEEF", "bx", "0xBEEF"),
    LoadTestCase(8, "mov", "", "", "ah", "0xDE", "bl", "0xDE"),
    LoadTestCase(8, "mov", "", "", "al", "0xDE", "bl", "0xDE"),
    
    # Test aliased registers that don't clear (e.g. ax, ah, al)
    LoadTestCase(16, "mov", "rax", "-1", "ax", "0x0000", "rbx", "0xFFFFFFFFFFFF0000"),
    LoadTestCase(16, "mov", "rax", "0", "ax", "0xFFFF", "rbx", "0xFFFF"),
    LoadTestCase(8, "mov", "rax", "-1", "ah", "0x00", "rbx", "0xFFFFFFFFFFFF00FF"),
    LoadTestCase(8, "mov", "rax", "0", "ah", "0xFF", "rbx", "0xFF00"),
    LoadTestCase(8, "mov", "rax", "-1", "al", "0x00", "rbx", "0xFFFFFFFFFFFFFF00"),
    LoadTestCase(8, "mov", "rax", "0", "al", "0xFF", "rbx", "0x00FF"),

    # Test zero extension (movzx)
    LoadTestCase(16, "movzx", "", "", "rax", "0xCAFE", "", "0xCAFE"),
    LoadTestCase(8, "movzx", "", "", "rax", "0xCA", "", "0xCA"),
    LoadTestCase(16, "movzx", "", "", "eax", "0xCAFE", "", "0xCAFE"),
    LoadTestCase(8, "movzx", "", "", "eax", "0xCA", "", "0xCA"),
    LoadTestCase(8, "movzx", "", "", "ax", "0xCA", "", "0xCA"),

    # Test zero extension on ax (shouldn't clear top 48 bits)
    LoadTestCase(8, "movzx", "rax", "-1", "ax", "0xCA", "rbx", "0xFFFFFFFFFFFF00CA"),

    # Test sign extension (movsx, movsxd)
    LoadTestCase(32, "movsxd", "", "", "rax", "0xFFFFFFFF", "", -1),
    LoadTestCase(16, "movsx", "", "", "rax", "0xFFFF", "", -1),
    LoadTestCase(8, "movsx", "", "", "rax", "0xFF", "", -1),
    LoadTestCase(8, "movsx", "", "", "eax", "0xFF", "", -1),
    LoadTestCase(8, "movsx", "", "", "ax", "0xFF", "", -1),

    # Make sure sign extension to 32-bit reg doesn't affect top 32 bits
    LoadTestCase(16, "movsx", "", "", "ecx", "0xFFFF", "", -1),
    AluTestCase(64, "mov", "rax", "", "rcx", "", "0xFFFFFFFF", "rbx"),
]

ALU_TESTS = [
    # SUB
    #AluTestCase(64, "sub", "rax", "rbx", "100", "99", "1"),
    #AluTestCase(64, "sub", "rax", "rbx", "0", "1", "-1"),
    #AluTestCase(64, "sub", "rax", "rbx", "1", "1", "0"),

    #AluTestCase(32, "sub", "eax", "ebx", "100", "99", "1"),
    #AluTestCase(32, "sub", "eax", "ebx", "0", "1", "-1"),
    #AluTestCase(32, "sub", "eax", "ebx", "1", "1", "0"),

    #AluTestCase(16, "sub", "ax", "bx", "100", "99", "1"),
    #AluTestCase(16, "sub", "ax", "bx", "0", "1", "-1"),
    #AluTestCase(16, "sub", "ax", "bx", "1", "1", "0"),

    #AluTestCase(8, "sub", "ah", "bh", "100", "99", "1"),
    #AluTestCase(8, "sub", "ah", "bh", "0", "1", "-1"),
    #AluTestCase(8, "sub", "ah", "bh", "1", "1", "0"),

    #AluTestCase(8, "sub", "al", "bl", "100", "99", "1"),
    #AluTestCase(8, "sub", "al", "bl", "0", "1", "-1"),
    #AluTestCase(8, "sub", "al", "bl", "1", "1", "0"),

    ## ADD
    #AluTestCase(64, "add", "rax", "rbx", "1", "99", "100"),
    #AluTestCase(64, "add", "rax", "rbx", "0", "1", "1"),
    #AluTestCase(64, "add", "rax", "rbx", "1", "1", "2"),
    #AluTestCase(64, "add", "rax", "rbx", "1", "-1", "0"),
    #AluTestCase(64, "add", "rax", "rbx", "1", "-2", "-1"),

    #AluTestCase(32, "add", "eax", "ebx", "1", "99", "100"),
    #AluTestCase(32, "add", "eax", "ebx", "0", "1", "1"),
    #AluTestCase(32, "add", "eax", "ebx", "1", "1", "2"),
    #AluTestCase(32, "add", "eax", "ebx", "1", "-1", "0"),
    #AluTestCase(32, "add", "eax", "ebx", "1", "-2", "-1"),

    #AluTestCase(16, "add", "ax", "bx", "1", "99", "100"),
    #AluTestCase(16, "add", "ax", "bx", "0", "1", "1"),
    #AluTestCase(16, "add", "ax", "bx", "1", "1", "2"),
    #AluTestCase(16, "add", "ax", "bx", "1", "-1", "0"),
    #AluTestCase(16, "add", "ax", "bx", "1", "-2", "-1"),

    #AluTestCase(8, "add", "ah", "bh", "1", "99", "100"),
    #AluTestCase(8, "add", "ah", "bh", "0", "1", "1"),
    #AluTestCase(8, "add", "ah", "bh", "1", "1", "2"),
    #AluTestCase(8, "add", "ah", "bh", "1", "-1", "0"),
    #AluTestCase(8, "add", "ah", "bh", "1", "-2", "-1"),

    #AluTestCase(8, "add", "al", "bl", "1", "99", "100"),
    #AluTestCase(8, "add", "al", "bl", "0", "1", "1"),
    #AluTestCase(8, "add", "al", "bl", "1", "1", "2"),
    #AluTestCase(8, "add", "al", "bl", "1", "-1", "0"),
    #AluTestCase(8, "add", "al", "bl", "1", "-2", "-1"),

    ## XOR
    #AluTestCase(64, "xor", "rax", "rbx", "0xFFFFFFFF", "0xFF000000", "0x00FFFFFF"),
    #AluTestCase(32, "xor", "eax", "ebx", "0xFFFFFFFF", "0xFF000000", "0x00FFFFFF"),
    #AluTestCase(16, "xor", "ax", "bx", "0xFFFF", "0xFF00", "0x00FF"),
    #AluTestCase(8, "xor", "ah", "bl", "0xFF", "0xF0", "0x0F"),
    #AluTestCase(8, "xor", "al", "bl", "0xFF", "0xF0", "0x0F"),

    ## AND
    #AluTestCase(64, "and", "rax", "rbx", "0xFFFFFFFFFFFFFFFF", "0xFFFF", "0xFFFF"),
    #AluTestCase(32, "and", "eax", "ebx", "0xFFFFFFFF", "0xFFFF", "0xFFFF"),
    #AluTestCase(16, "and", "ax", "bx", "0xFFFF", "0xFF", "0xFF"),
    #AluTestCase(8, "and", "ah", "bl", "0xFF", "0xF0", "0xF0"),
    #AluTestCase(8, "and", "al", "bl", "0xFF", "0xF0", "0xF0"),

    ## MOVZX reg, reg
    #AluTestCase(16, "movzx", "rax", "bx", "0", "-1", "0xFFFF"),
    #AluTestCase(8,  "movzx", "rax", "bl", "0", "-1", "0xFF"),
    #AluTestCase(16, "movzx", "eax", "bx", "0", "-1", "0xFFFF"),
    #AluTestCase(8,  "movzx", "eax", "bl", "0", "-1", "0xFF"),
    #AluTestCase(8,  "movzx", "ax", "bl", "0", "-1", "0xFF"),

    ## MOVSX reg, reg
    #AluTestCase(32, "movsx", "rax", "ebx", "0", "-1", "-1"),
    #AluTestCase(16, "movsx", "rax", "bx", "0", "-1", "-1"),
    #AluTestCase(8,  "movsx", "rax", "bl", "0", "-1", "-1"),
    #AluTestCase(16, "movsx", "eax", "bx", "0", "-1", "-1"),
    #AluTestCase(8,  "movsx", "eax", "bl", "0", "-1", "-1"),
    #AluTestCase(8,  "movsx", "ax", "bl", "0", "-1", "-1"),

    ## IMUL 2-operand
    #AluTestCase(64, "imul", "rax", "rbx", "-1", "-1", "1"),
    #AluTestCase(64, "imul", "rax", "rbx", "-1", "1", "-1"),
    #AluTestCase(64, "imul", "rax", "rbx", "0x3fffffffffffffff", "2", "0x7ffffffffffffffe", "rcx"),
    #AluTestCase(64, "imul", "rax", "rbx", "0x4000000000000000", "2", "0x8000000000000000", "rcx"),

    #AluTestCase(32, "imul", "eax", "ebx", "-1", "-1", "1"),
    #AluTestCase(32, "imul", "eax", "ebx", "-1", "1", "-1"),
    #AluTestCase(32, "imul", "eax", "ebx", "0x3fffffff", "2", "0x7ffffffe"),
    #AluTestCase(32, "imul", "eax", "ebx", "0x40000000", "2", "0x80000000"),

    #AluTestCase(16, "imul", "ax", "bx", "-1", "-1", "1"),
    #AluTestCase(16, "imul", "ax", "bx", "-1", "1", "-1"),
    #AluTestCase(16, "imul", "ax", "bx", "0x3fff", "2", "0x7ffe"),
    #AluTestCase(16, "imul", "ax", "bx", "0x4000", "2", "0x8000"),

    ## IMUL 1-operand
    ##
    ## These tests look a little weird because they use comment injection to
    ## override the exact instruction used, and they also compare the result
    ## of the high bytes with a second pop+cmp test.
    #AluTestCase(64, "imul rbx; push rdx#", "rax", "rbx", "-1", "-1", "1"),
    #AluTestCase(64, "pop rdx#", "rdx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(64, "imul rbx; push rdx#", "rax", "rbx", "-1", "1", "-1"),
    #AluTestCase(64, "pop rdx#", "rdx", "", "0", "", "-1"), # high should be all 1
    #AluTestCase(64, "imul rbx; push rdx#", "rax", "rbx", "0x3fffffffffffffff", "2", "0x7ffffffffffffffe", "rcx"),
    #AluTestCase(64, "pop rdx#", "rdx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(64, "imul rbx; push rdx#", "rax", "rbx", "0x4000000000000000", "2", "0x8000000000000000", "rcx"),
    #AluTestCase(64, "pop rdx#", "rdx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(64, "imul rbx; push rdx#", "rax", "rbx", "0x7fffffffffffffff", "3", "0x7ffffffffffffffd", "rcx"),
    #AluTestCase(64, "pop rdx#", "rdx", "", "0", "", "1"), # high should be exactly 1

    #AluTestCase(32, "imul ebx; push rdx#", "eax", "ebx", "-1", "-1", "1"),
    #AluTestCase(32, "pop rdx#", "edx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(32, "imul ebx; push rdx#", "eax", "ebx", "-1", "1", "-1"),
    #AluTestCase(32, "pop rdx#", "edx", "", "0", "", "-1"), # high should be all 1
    #AluTestCase(32, "imul ebx; push rdx#", "eax", "ebx", "0x3fffffff", "2", "0x7ffffffe"),
    #AluTestCase(32, "pop rdx#", "edx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(32, "imul ebx; push rdx#", "eax", "ebx", "0x40000000", "2", "0x80000000"),
    #AluTestCase(32, "pop rdx#", "edx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(32, "imul ebx; push rdx#", "eax", "ebx", "0x7fffffff", "3", "0x7ffffffd"),
    #AluTestCase(32, "pop rdx#", "edx", "", "0", "", "1"), # high should be exactly 1

    #AluTestCase(16, "imul bx; push rdx#", "ax", "bx", "-1", "-1", "1"),
    #AluTestCase(16, "pop rdx#", "dx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(16, "imul bx; push rdx#", "ax", "bx", "-1", "1", "-1"),
    #AluTestCase(16, "pop rdx#", "dx", "", "0", "", "-1"), # high should be all 1
    #AluTestCase(16, "imul bx; push rdx#", "ax", "bx", "0x3fff", "2", "0x7ffe"),
    #AluTestCase(16, "pop rdx#", "dx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(16, "imul bx; push rdx#", "ax", "bx", "0x4000", "2", "0x8000"),
    #AluTestCase(16, "pop rdx#", "dx", "", "0", "", "0"), # high should be all 0
    #AluTestCase(16, "imul bx; push rdx#", "ax", "bx", "0x7fff", "3", "0x7ffd"),
    #AluTestCase(16, "pop rdx#", "dx", "", "0", "", "1"), # high should be exactly 1

    #AluTestCase(8, "imul bl#", "al", "bl", "-1", "-1", "1"),
    #AluTestCase(8, "imul bl#", "al", "bl", "-1", "1", "-1"),
    #AluTestCase(8, "imul bl#", "al", "bl", "0x3f", "2", "0x7e"),
    #AluTestCase(8, "imul bl#", "al", "bl", "0x40", "2", "0x80"),

    # S{A,H}{R,L}
    AluTestCase(64, "shl", "rax", "1", "1", "", "2"),
    AluTestCase(64, "shl", "rax", "2", "1", "", "4"),
    AluTestCase(64, "shl", "rax", "cl", "1", "1", "2"),
    AluTestCase(64, "shr", "rax", "1", "1", "", "0"),
    AluTestCase(64, "shr", "rax", "1", "2", "", "1"),
    AluTestCase(64, "shr", "rax", "cl", "2", "1", "1"),
    AluTestCase(64, "sar", "rax", "1", "1", "", "0"),
    AluTestCase(64, "sar", "rax", "1", "2", "", "1"),
    AluTestCase(64, "sar", "rax", "cl", "2", "1", "1"),
    AluTestCase(64, "sar", "rax", "1", "-1", "", "-1"),
    AluTestCase(64, "sar", "rax", "1", "-3", "", "-2"),
    AluTestCase(64, "sar", "rax", "cl", "-3", "1", "-2"),

    AluTestCase(32, "shl", "eax", "1", "1", "", "2"),
    AluTestCase(32, "shl", "eax", "2", "1", "", "4"),
    AluTestCase(32, "shl", "eax", "cl", "1", "1", "2"),
    AluTestCase(32, "shr", "eax", "1", "1", "", "0"),
    AluTestCase(32, "shr", "eax", "1", "2", "", "1"),
    AluTestCase(32, "shr", "eax", "cl", "2", "1", "1"),
    AluTestCase(32, "sar", "eax", "1", "1", "", "0"),
    AluTestCase(32, "sar", "eax", "1", "2", "", "1"),
    AluTestCase(32, "sar", "eax", "cl", "2", "1", "1"),
    AluTestCase(32, "sar", "eax", "1", "-1", "", "-1"),
    AluTestCase(32, "sar", "eax", "1", "-3", "", "-2"),
    AluTestCase(32, "sar", "eax", "cl", "-3", "1", "-2"),

    AluTestCase(16, "shl", "ax", "1", "1", "", "2"),
    AluTestCase(16, "shl", "ax", "2", "1", "", "4"),
    AluTestCase(16, "shl", "ax", "cl", "1", "1", "2"),
    AluTestCase(16, "shr", "ax", "1", "1", "", "0"),
    AluTestCase(16, "shr", "ax", "1", "2", "", "1"),
    AluTestCase(16, "shr", "ax", "cl", "2", "1", "1"),
    AluTestCase(16, "sar", "ax", "1", "1", "", "0"),
    AluTestCase(16, "sar", "ax", "1", "2", "", "1"),
    AluTestCase(16, "sar", "ax", "cl", "2", "1", "1"),
    AluTestCase(16, "sar", "ax", "1", "-1", "", "-1"),
    AluTestCase(16, "sar", "ax", "1", "-3", "", "-2"),
    AluTestCase(16, "sar", "ax", "cl", "-3", "1", "-2"),

    AluTestCase(8, "shl", "ah", "1", "1", "", "2"),
    AluTestCase(8, "shl", "ah", "2", "1", "", "4"),
    AluTestCase(8, "shl", "ah", "cl", "1", "1", "2"),
    AluTestCase(8, "shr", "ah", "1", "1", "", "0"),
    AluTestCase(8, "shr", "ah", "1", "2", "", "1"),
    AluTestCase(8, "shr", "ah", "cl", "2", "1", "1"),
    AluTestCase(8, "sar", "ah", "1", "1", "", "0"),
    AluTestCase(8, "sar", "ah", "1", "2", "", "1"),
    AluTestCase(8, "sar", "ah", "cl", "2", "1", "1"),
    AluTestCase(8, "sar", "ah", "1", "-1", "", "-1"),
    AluTestCase(8, "sar", "ah", "1", "-3", "", "-2"),
    AluTestCase(8, "sar", "ah", "cl", "-3", "1", "-2"),

    AluTestCase(8, "shl", "al", "1", "1", "", "2"),
    AluTestCase(8, "shl", "al", "2", "1", "", "4"),
    AluTestCase(8, "shl", "al", "cl", "1", "1", "2"),
    AluTestCase(8, "shr", "al", "1", "1", "", "0"),
    AluTestCase(8, "shr", "al", "1", "2", "", "1"),
    AluTestCase(8, "shr", "al", "cl", "2", "1", "1"),
    AluTestCase(8, "sar", "al", "1", "1", "", "0"),
    AluTestCase(8, "sar", "al", "1", "2", "", "1"),
    AluTestCase(8, "sar", "al", "cl", "2", "1", "1"),
    AluTestCase(8, "sar", "al", "1", "-1", "", "-1"),
    AluTestCase(8, "sar", "al", "1", "-3", "", "-2"),
    AluTestCase(8, "sar", "al", "cl", "-3", "1", "-2"),
]

CARRY_TESTS = [
    # SUB (cmp)
    #FlagTestCase(64, "rax", "rbx", "0", "-1", "cmp", "jc", "jnc"),
    #FlagTestCase(64, "rax", "rbx", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(64, "rax", "", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(32, "eax", "ebx", "1", "-1", "cmp", "jc", "jnc"),
    #FlagTestCase(32, "eax", "ebx", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(32, "eax", "", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(16, "ax", "bx", "0", "-1", "cmp", "jc", "jnc"),
    #FlagTestCase(16, "ax", "bx", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(16, "ax", "", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(8, "ah", "bh", "0", "-1", "cmp", "jc", "jnc"),
    #FlagTestCase(8, "ah", "bh", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(8, "ah", "", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(8, "al", "bl", "0", "-1", "cmp", "jc", "jnc"),
    #FlagTestCase(8, "al", "bl", "-1", "-1", "cmp", "jnc", "jc"),
    #FlagTestCase(8, "al", "", "-1", "-1", "cmp", "jnc", "jc"),

    ## IMUL
    #FlagTestCase(64, "rax", "rbx", "0x7FFFFFFFFFFFFFF", "17", "imul", "jc", "jnc"),
    #FlagTestCase(64, "rax", "rbx", "0x7FFFFFFFFFFFFFF", "16", "imul", "jnc", "jc"),
    #FlagTestCase(64, "rax", "rbx", "0x7FFFFFFFFFFFFFF", "-17", "imul", "jc", "jnc"),
    #FlagTestCase(64, "rax", "rbx", "0x7FFFFFFFFFFFFFF", "-16", "imul", "jnc", "jc"),
    #FlagTestCase(64, "rax", "rbx", "0x800000000000000", "16", "imul", "jc", "jnc"),
    #FlagTestCase(64, "rax", "rbx", "0x800000000000000", "15", "imul", "jnc", "jc"),
    #FlagTestCase(64, "rax", "rbx", "0x800000000000000", "-17", "imul", "jc", "jnc"),
    #FlagTestCase(64, "rax", "rbx", "0x800000000000000", "-16", "imul", "jnc", "jc"),
    #FlagTestCase(64, "rax", "rbx", "0", "0", "imul", "jnc", "jc"),

    #FlagTestCase(32, "eax", "ebx", "0x7FFFFFF", "17", "imul", "jc", "jnc"),
    #FlagTestCase(32, "eax", "ebx", "0x7FFFFFF", "16", "imul", "jnc", "jc"),
    #FlagTestCase(32, "eax", "ebx", "0x7FFFFFF", "-17", "imul", "jc", "jnc"),
    #FlagTestCase(32, "eax", "ebx", "0x7FFFFFF", "-16", "imul", "jnc", "jc"),
    #FlagTestCase(32, "eax", "ebx", "0x8000000", "16", "imul", "jc", "jnc"),
    #FlagTestCase(32, "eax", "ebx", "0x8000000", "15", "imul", "jnc", "jc"),
    #FlagTestCase(32, "eax", "ebx", "0x8000000", "-17", "imul", "jc", "jnc"),
    #FlagTestCase(32, "eax", "ebx", "0x8000000", "-16", "imul", "jnc", "jc"),
    #FlagTestCase(32, "eax", "ebx", "0", "0", "imul", "jnc", "jc"),

    #FlagTestCase(16, "ax", "bx", "0x7FF", "17", "imul", "jc", "jnc"),
    #FlagTestCase(16, "ax", "bx", "0x7FF", "16", "imul", "jnc", "jc"),
    #FlagTestCase(16, "ax", "bx", "0x7FF", "-17", "imul", "jc", "jnc"),
    #FlagTestCase(16, "ax", "bx", "0x7FF", "-16", "imul", "jnc", "jc"),
    #FlagTestCase(16, "ax", "bx", "0x800", "16", "imul", "jc", "jnc"),
    #FlagTestCase(16, "ax", "bx", "0x800", "15", "imul", "jnc", "jc"),
    #FlagTestCase(16, "ax", "bx", "0x800", "-17", "imul", "jc", "jnc"),
    #FlagTestCase(16, "ax", "bx", "0x800", "-16", "imul", "jnc", "jc"),
    #FlagTestCase(16, "ax", "bx", "0", "0", "imul", "jnc", "jc"),

    #FlagTestCase(8, "al", "bl", "0x8", "17", "imul bl#", "jc", "jnc"),
    #FlagTestCase(8, "al", "bl", "0x8", "15", "imul bl#", "jnc", "jc"),
    #FlagTestCase(8, "al", "bl", "0x8", "-17", "imul bl#", "jc", "jnc"),
    #FlagTestCase(8, "al", "bl", "0x8", "-16", "imul bl#", "jnc", "jc"),

    # Shifts
    FlagTestCase(64, "rax", "", "1", "1", "shr", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-1", "1", "shr", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-2", "1", "shr", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "2", "2", "shr", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-1", "2", "shr", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-4", "2", "shr", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "0x4000000000000000", "63", "shr", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "1", "1", "sar", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-1", "1", "sar", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-2", "1", "sar", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "2", "2", "sar", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-1", "2", "sar", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-4", "2", "sar", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "0x4000000000000000", "63", "sar", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "0x8000000000000000", "1", "shl", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-1", "1", "shl", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "0x7FFFFFFFFFFFFFFF", "1", "shl", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "0x4000000000000000", "2", "shl", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "-1", "2", "shl", "jc", "jnc"),
    FlagTestCase(64, "rax", "", "0x3FFFFFFFFFFFFFFF", "2", "shl", "jnc", "jc"),
    FlagTestCase(64, "rax", "", "2", "63", "shl", "jc", "jnc"),

    FlagTestCase(32, "eax", "", "1", "1", "shr", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-1", "1", "shr", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-2", "1", "shr", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "2", "2", "shr", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-1", "2", "shr", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-4", "2", "shr", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "0x40000000", "31", "shr", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "1", "1", "sar", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-1", "1", "sar", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-2", "1", "sar", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "2", "2", "sar", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-1", "2", "sar", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-4", "2", "sar", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "0x40000000", "31", "sar", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "0x80000000", "1", "shl", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-1", "1", "shl", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "0x7FFFFFFF", "1", "shl", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "0x40000000", "2", "shl", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "-1", "2", "shl", "jc", "jnc"),
    FlagTestCase(32, "eax", "", "0x3FFFFFFF", "2", "shl", "jnc", "jc"),
    FlagTestCase(32, "eax", "", "2", "31", "shl", "jc", "jnc"),

    FlagTestCase(16, "ax", "", "1", "1", "shr", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-1", "1", "shr", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-2", "1", "shr", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "2", "2", "shr", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-1", "2", "shr", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-4", "2", "shr", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "0x4000", "15", "shr", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "1", "1", "sar", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-1", "1", "sar", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-2", "1", "sar", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "2", "2", "sar", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-1", "2", "sar", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-4", "2", "sar", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "0x4000", "15", "sar", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "0x8000", "1", "shl", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-1", "1", "shl", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "0x7FFF", "1", "shl", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "0x4000", "2", "shl", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "-1", "2", "shl", "jc", "jnc"),
    FlagTestCase(16, "ax", "", "0x3FFF", "2", "shl", "jnc", "jc"),
    FlagTestCase(16, "ax", "", "2", "15", "shl", "jc", "jnc"),

    FlagTestCase(8, "ah", "", "1", "1", "shr", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-1", "1", "shr", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-2", "1", "shr", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "2", "2", "shr", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-1", "2", "shr", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-4", "2", "shr", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "0x40", "7", "shr", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "1", "1", "sar", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-1", "1", "sar", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-2", "1", "sar", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "2", "2", "sar", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-1", "2", "sar", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-4", "2", "sar", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "0x40", "7", "sar", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "0x80", "1", "shl", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-1", "1", "shl", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "0x7F", "1", "shl", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "0x40", "2", "shl", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "-1", "2", "shl", "jc", "jnc"),
    FlagTestCase(8, "ah", "", "0x3F", "2", "shl", "jnc", "jc"),
    FlagTestCase(8, "ah", "", "2", "7", "shl", "jc", "jnc"),

    FlagTestCase(8, "al", "", "1", "1", "shr", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-1", "1", "shr", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-2", "1", "shr", "jnc", "jc"),
    FlagTestCase(8, "al", "", "2", "2", "shr", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-1", "2", "shr", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-4", "2", "shr", "jnc", "jc"),
    FlagTestCase(8, "al", "", "0x40", "7", "shr", "jc", "jnc"),
    FlagTestCase(8, "al", "", "1", "1", "sar", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-1", "1", "sar", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-2", "1", "sar", "jnc", "jc"),
    FlagTestCase(8, "al", "", "2", "2", "sar", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-1", "2", "sar", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-4", "2", "sar", "jnc", "jc"),
    FlagTestCase(8, "al", "", "0x40", "7", "sar", "jc", "jnc"),
    FlagTestCase(8, "al", "", "0x80", "1", "shl", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-1", "1", "shl", "jc", "jnc"),
    FlagTestCase(8, "al", "", "0x7F", "1", "shl", "jnc", "jc"),
    FlagTestCase(8, "al", "", "0x40", "2", "shl", "jc", "jnc"),
    FlagTestCase(8, "al", "", "-1", "2", "shl", "jc", "jnc"),
    FlagTestCase(8, "al", "", "0x3F", "2", "shl", "jnc", "jc"),
    FlagTestCase(8, "al", "", "2", "7", "shl", "jc", "jnc"),
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
    FlagTestCase(64, "rax", "", "0x8000000000000000", "-1", "add", "jo", "jno"), # Positive overflow
    FlagTestCase(64, "rax", "", "0x7FFFFFFFFFFFFFFF", "1", "add", "jo", "jno"), # Negative overflow
    FlagTestCase(64, "rax", "", "0", "-1", "add", "jno", "jo"), # No overflow
    FlagTestCase(64, "rax", "", "-1", "-1", "add", "jno", "jo"), # No overflow

    FlagTestCase(32, "eax", "", "0x80000000", "-1", "add", "jo", "jno"), # Positive overflow
    FlagTestCase(32, "eax", "", "0x7FFFFFFF", "1", "add", "jo", "jno"), # Negative overflow
    FlagTestCase(32, "eax", "", "0", "-1", "add", "jno", "jo"), # No overflow
    FlagTestCase(32, "eax", "", "-1", "-1", "add", "jno", "jo"), # No overflow

    FlagTestCase(16, "ax", "", "0x8000", "-1", "add", "jo", "jno"), # Positive overflow
    FlagTestCase(16, "ax", "", "0x7FFF", "1", "add", "jo", "jno"), # Negative overflow
    FlagTestCase(16, "ax", "", "0", "-1", "add", "jno", "jo"), # No overflow
    FlagTestCase(16, "ax", "", "-1", "-1", "add", "jno", "jo"), # No overflow

    FlagTestCase(8, "ah", "", "0x80", "-1", "add", "jo", "jno"), # Positive overflow
    FlagTestCase(8, "ah", "", "0x7F", "1", "add", "jo", "jno"), # Negative overflow
    FlagTestCase(8, "ah", "", "0", "-1", "add", "jno", "jo"), # No overflow
    FlagTestCase(8, "ah", "", "-1", "-1", "add", "jno", "jo"), # No overflow

    FlagTestCase(8, "al", "", "0x80", "-1", "add", "jo", "jno"), # Positive overflow
    FlagTestCase(8, "al", "", "0x7F", "1", "add", "jo", "jno"), # Negative overflow
    FlagTestCase(8, "al", "", "0", "-1", "add", "jno", "jo"), # No overflow
    FlagTestCase(8, "al", "", "-1", "-1", "add", "jno", "jo"), # No overflow

    # Shifts
    FlagTestCase(64, "rax", "", "0xC000000000000000", "1", "shl", "jno", "jo"),
    FlagTestCase(64, "rax", "", "0", "1", "shl", "jno", "jo"),
    FlagTestCase(64, "rax", "", "0x8000000000000000", "1", "shl", "jo", "jno"),
    FlagTestCase(64, "rax", "", "0x4000000000000000", "1", "shl", "jo", "jno"),
    FlagTestCase(64, "rax", "", "0x8000000000000000", "1", "shr", "jo", "jno"),
    FlagTestCase(64, "rax", "", "0", "1", "shr", "jno", "jo"),
    FlagTestCase(64, "rax", "", "0x8000000000000000", "1", "sar", "jno", "jo"),
    FlagTestCase(64, "rax", "", "0", "1", "sar", "jno", "jo"),

    FlagTestCase(32, "eax", "", "0xC0000000", "1", "shl", "jno", "jo"),
    FlagTestCase(32, "eax", "", "0", "1", "shl", "jno", "jo"),
    FlagTestCase(32, "eax", "", "0x80000000", "1", "shl", "jo", "jno"),
    FlagTestCase(32, "eax", "", "0x40000000", "1", "shl", "jo", "jno"),
    FlagTestCase(32, "eax", "", "0x80000000", "1", "shr", "jo", "jno"),
    FlagTestCase(32, "eax", "", "0", "1", "shr", "jno", "jo"),
    FlagTestCase(32, "eax", "", "0x80000000", "1", "sar", "jno", "jo"),
    FlagTestCase(32, "eax", "", "0", "1", "sar", "jno", "jo"),

    FlagTestCase(16, "ax", "", "0xC000", "1", "shl", "jno", "jo"),
    FlagTestCase(16, "ax", "", "0", "1", "shl", "jno", "jo"),
    FlagTestCase(16, "ax", "", "0x8000", "1", "shl", "jo", "jno"),
    FlagTestCase(16, "ax", "", "0x4000", "1", "shl", "jo", "jno"),
    FlagTestCase(16, "ax", "", "0x8000", "1", "shr", "jo", "jno"),
    FlagTestCase(16, "ax", "", "0", "1", "shr", "jno", "jo"),
    FlagTestCase(16, "ax", "", "0x8000", "1", "sar", "jno", "jo"),
    FlagTestCase(16, "ax", "", "0", "1", "sar", "jno", "jo"),

    FlagTestCase(8, "ah", "", "0xC0", "1", "shl", "jno", "jo"),
    FlagTestCase(8, "ah", "", "0", "1", "shl", "jno", "jo"),
    FlagTestCase(8, "ah", "", "0x80", "1", "shl", "jo", "jno"),
    FlagTestCase(8, "ah", "", "0x40", "1", "shl", "jo", "jno"),
    FlagTestCase(8, "ah", "", "0x80", "1", "shr", "jo", "jno"),
    FlagTestCase(8, "ah", "", "0", "1", "shr", "jno", "jo"),
    FlagTestCase(8, "ah", "", "0x80", "1", "sar", "jno", "jo"),
    FlagTestCase(8, "ah", "", "0", "1", "sar", "jno", "jo"),

    FlagTestCase(8, "al", "", "0xC0", "1", "shl", "jno", "jo"),
    FlagTestCase(8, "al", "", "0", "1", "shl", "jno", "jo"),
    FlagTestCase(8, "al", "", "0x80", "1", "shl", "jo", "jno"),
    FlagTestCase(8, "al", "", "0x40", "1", "shl", "jo", "jno"),
    FlagTestCase(8, "al", "", "0x80", "1", "shr", "jo", "jno"),
    FlagTestCase(8, "al", "", "0", "1", "shr", "jno", "jo"),
    FlagTestCase(8, "al", "", "0x80", "1", "sar", "jno", "jo"),
    FlagTestCase(8, "al", "", "0", "1", "sar", "jno", "jo"),

]

ABOVE_TESTS = [
    FlagTestCase(64, "rax", "", "1", "0", "cmp", "ja", "jb"), # !CF, !ZF
    FlagTestCase(64, "rax", "", "1", "1", "cmp", "jbe", "ja"), # !CF, ZF
    FlagTestCase(64, "rax", "", "1", "-1", "cmp", "jbe", "ja"), # CF, !ZF

    FlagTestCase(32, "eax", "", "1", "0", "cmp", "ja", "jb"), # !CF, !ZF
    FlagTestCase(32, "eax", "", "1", "1", "cmp", "jbe", "ja"), # !CF, ZF
    FlagTestCase(32, "eax", "", "1", "-1", "cmp", "jbe", "ja"), # CF, !ZF

    FlagTestCase(16, "ax", "", "1", "0", "cmp", "ja", "jb"), # !CF, !ZF
    FlagTestCase(16, "ax", "", "1", "1", "cmp", "jbe", "ja"), # !CF, ZF
    FlagTestCase(16, "ax", "", "1", "-1", "cmp", "jbe", "ja"), # CF, !ZF

    FlagTestCase(8, "ah", "", "1", "0", "cmp", "ja", "jb"), # !CF, !ZF
    FlagTestCase(8, "ah", "", "1", "1", "cmp", "jbe", "ja"), # !CF, ZF
    FlagTestCase(8, "ah", "", "1", "-1", "cmp", "jbe", "ja"), # CF, !ZF

    FlagTestCase(8, "al", "", "1", "0", "cmp", "ja", "jb"), # !CF, !ZF
    FlagTestCase(8, "al", "", "1", "1", "cmp", "jbe", "ja"), # !CF, ZF
    FlagTestCase(8, "al", "", "1", "-1", "cmp", "jbe", "ja"), # CF, !ZF
]

GREATER_EQ_TESTS = [
    FlagTestCase(64, "rax", "", "-1", "-2", "cmp", "jge", "jl"), # SF=OF=1
    FlagTestCase(64, "rax", "", "-2", "-1", "cmp", "jl", "jge"), # SF=1, OF=0
    FlagTestCase(64, "rax", "", "-1", "1", "cmp", "jl", "jge"), # SF=0, OF=1
    FlagTestCase(64, "rax", "", "1", "0", "cmp", "jge", "jl"), # SF=OF=0

    FlagTestCase(32, "eax", "", "-1", "-2", "cmp", "jge", "jl"), # SF=OF=1
    FlagTestCase(32, "eax", "", "-2", "-1", "cmp", "jl", "jge"), # SF=1, OF=0
    FlagTestCase(32, "eax", "", "-1", "1", "cmp", "jl", "jge"), # SF=0, OF=1
    FlagTestCase(32, "eax", "", "1", "0", "cmp", "jge", "jl"), # SF=OF=0

    FlagTestCase(16, "ax", "", "-1", "-2", "cmp", "jge", "jl"), # SF=OF=1
    FlagTestCase(16, "ax", "", "-2", "-1", "cmp", "jl", "jge"), # SF=1, OF=0
    FlagTestCase(16, "ax", "", "-1", "1", "cmp", "jl", "jge"), # SF=0, OF=1
    FlagTestCase(16, "ax", "", "1", "0", "cmp", "jge", "jl"), # SF=OF=0

    FlagTestCase(8, "ah", "", "-1", "-2", "cmp", "jge", "jl"), # SF=OF=1
    FlagTestCase(8, "ah", "", "-2", "-1", "cmp", "jl", "jge"), # SF=1, OF=0
    FlagTestCase(8, "ah", "", "-1", "1", "cmp", "jl", "jge"), # SF=0, OF=1
    FlagTestCase(8, "ah", "", "1", "0", "cmp", "jge", "jl"), # SF=OF=0

    FlagTestCase(8, "al", "", "-1", "-2", "cmp", "jge", "jl"), # SF=OF=1
    FlagTestCase(8, "al", "", "-2", "-1", "cmp", "jl", "jge"), # SF=1, OF=0
    FlagTestCase(8, "al", "", "-1", "1", "cmp", "jl", "jge"), # SF=0, OF=1
    FlagTestCase(8, "al", "", "1", "0", "cmp", "jge", "jl"), # SF=OF=0
]

SIGN_TESTS = [
    # CMP
    FlagTestCase(64, "rax", "", "0", "1", "cmp", "js", "jns"), # SF=1
    FlagTestCase(64, "rax", "", "1", "1", "cmp", "jns", "js"),  # SF=0
    FlagTestCase(64, "rax", "", "0", "-1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(64, "rax", "", "-1", "1", "cmp", "js", "jns"), # SF=1

    FlagTestCase(32, "eax", "", "0", "1", "cmp", "js", "jns"), # SF=1
    FlagTestCase(32, "eax", "", "1", "1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(32, "eax", "", "0", "-1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(32, "eax", "", "-1", "1", "cmp", "js", "jns"), # SF=1

    FlagTestCase(16, "ax", "", "0", "1", "cmp", "js", "jns"), # SF=1
    FlagTestCase(16, "ax", "", "1", "1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(16, "ax", "", "0", "-1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(16, "ax", "", "-1", "1", "cmp", "js", "jns"), # SF=1

    FlagTestCase(8, "ah", "", "0", "1", "cmp", "js", "jns"), # SF=1
    FlagTestCase(8, "ah", "", "1", "1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(8, "ah", "", "0", "-1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(8, "ah", "", "-1", "1", "cmp", "js", "jns"), # SF=1

    FlagTestCase(8, "al", "", "0", "1", "cmp", "js", "jns"), # SF=1
    FlagTestCase(8, "al", "", "1", "1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(8, "al", "", "0", "-1", "cmp", "jns", "js"), # SF=0
    FlagTestCase(8, "al", "", "-1", "1", "cmp", "js", "jns"), # SF=1

    # TEST
    FlagTestCase(64, "rax", "", "-1", "-1", "test", "js", "jns"), # SF=1
    FlagTestCase(64, "rax", "", "-1", "1", "test", "jns", "js"), # SF=0
    FlagTestCase(64, "rax", "", "1", "-1", "test", "jns", "js"), # SF=0
    FlagTestCase(64, "rax", "rbx", "-1", "0x8000000000000000", "test", "js", "jns"), # SF=1

    FlagTestCase(32, "eax", "", "-1", "-1", "test", "js", "jns"), # SF=1
    FlagTestCase(32, "eax", "", "-1", "1", "test", "jns", "js"), # SF=0
    FlagTestCase(32, "eax", "", "1", "-1", "test", "jns", "js"), # SF=0
    FlagTestCase(32, "eax", "", "-1", "0x80000000", "test", "js", "jns"), # SF=1

    FlagTestCase(16, "ax", "", "-1", "-1", "test", "js", "jns"), # SF=1
    FlagTestCase(16, "ax", "", "-1", "1", "test", "jns", "js"), # SF=0
    FlagTestCase(16, "ax", "", "1", "-1", "test", "jns", "js"), # SF=0
    FlagTestCase(16, "ax", "", "-1", "0x8000", "test", "js", "jns"), # SF=1

    FlagTestCase(8, "ah", "", "-1", "-1", "test", "js", "jns"), # SF=1
    FlagTestCase(8, "ah", "", "-1", "1", "test", "jns", "js"), # SF=0
    FlagTestCase(8, "ah", "", "1", "-1", "test", "jns", "js"), # SF=0
    FlagTestCase(8, "ah", "", "-1", "0x80", "test", "js", "jns"), # SF=1

    FlagTestCase(8, "al", "", "-1", "-1", "test", "js", "jns"), # SF=1
    FlagTestCase(8, "al", "", "-1", "1", "test", "jns", "js"), # SF=0
    FlagTestCase(8, "al", "", "1", "-1", "test", "jns", "js"), # SF=0
    FlagTestCase(8, "al", "", "-1", "0x80", "test", "js", "jns"), # SF=1
]

GREATER_TESTS = [
    FlagTestCase(64, "rax", "", "1", "0", "cmp", "jg", "jle"), # !ZF, !SF, !OF
    FlagTestCase(64, "rax", "", "0x7FFFFFFFFFFFFFFF", "-1", "cmp", "jg", "jle"), # !ZF, SF, OF
    FlagTestCase(64, "rax", "", "1", "1", "cmp", "jle", "jg"), # ZF, !SF, !OF
    FlagTestCase(64, "rax", "", "-1", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(64, "rax", "", "-2", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(64, "rax", "", "0", "1", "cmp", "jle", "jg"), # !ZF, SF, OF

    FlagTestCase(32, "eax", "", "1", "0", "cmp", "jg", "jle"), # !ZF, !SF, !OF
    FlagTestCase(32, "eax", "", "0x7FFFFFFF", "-1", "cmp", "jg", "jle"), # !ZF, SF, OF
    FlagTestCase(32, "eax", "", "1", "1", "cmp", "jle", "jg"), # ZF, !SF, !OF
    FlagTestCase(32, "eax", "", "-1", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(32, "eax", "", "-2", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(32, "eax", "", "0", "1", "cmp", "jle", "jg"), # !ZF, SF, OF

    FlagTestCase(16, "ax", "", "1", "0", "cmp", "jg", "jle"), # !ZF, !SF, !OF
    FlagTestCase(16, "ax", "", "0x7FFF", "-1", "cmp", "jg", "jle"), # !ZF, SF, OF
    FlagTestCase(16, "ax", "", "1", "1", "cmp", "jle", "jg"), # ZF, !SF, !OF
    FlagTestCase(16, "ax", "", "-1", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(16, "ax", "", "-2", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(16, "ax", "", "0", "1", "cmp", "jle", "jg"), # !ZF, SF, OF

    FlagTestCase(8, "ah", "", "1", "0", "cmp", "jg", "jle"), # !ZF, !SF, !OF
    FlagTestCase(8, "ah", "", "0x7F", "-1", "cmp", "jg", "jle"), # !ZF, SF, OF
    FlagTestCase(8, "ah", "", "1", "1", "cmp", "jle", "jg"), # ZF, !SF, !OF
    FlagTestCase(8, "ah", "", "-1", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(8, "ah", "", "-2", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(8, "ah", "", "0", "1", "cmp", "jle", "jg"), # !ZF, SF, OF

    FlagTestCase(8, "al", "", "1", "0", "cmp", "jg", "jle"), # !ZF, !SF, !OF
    FlagTestCase(8, "al", "", "0x7F", "-1", "cmp", "jg", "jle"), # !ZF, SF, OF
    FlagTestCase(8, "al", "", "1", "1", "cmp", "jle", "jg"), # ZF, !SF, !OF
    FlagTestCase(8, "al", "", "-1", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(8, "al", "", "-2", "-1", "cmp", "jle", "jg"), # ZF, !SF, OF
    FlagTestCase(8, "al", "", "0", "1", "cmp", "jle", "jg"), # !ZF, SF, OF
]

ZERO_TESTS = [
    # CMP
    FlagTestCase(64, "rax", "", "1", "1", "cmp", "je", "jne"), # ZF=1
    FlagTestCase(64, "rax", "", "0", "1", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(64, "rax", "", "1", "0", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(64, "rax", "", "0", "0", "cmp", "je", "jne"), # ZF=1

    FlagTestCase(32, "eax", "", "1", "1", "cmp", "je", "jne"), # ZF=1
    FlagTestCase(32, "eax", "", "0", "1", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(32, "eax", "", "1", "0", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(32, "eax", "", "0", "0", "cmp", "je", "jne"), # ZF=1

    FlagTestCase(16, "ax", "", "1", "1", "cmp", "je", "jne"), # ZF=1
    FlagTestCase(16, "ax", "", "0", "1", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(16, "ax", "", "1", "0", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(16, "ax", "", "0", "0", "cmp", "je", "jne"), # ZF=1

    FlagTestCase(8, "ah", "", "1", "1", "cmp", "je", "jne"), # ZF=1
    FlagTestCase(8, "ah", "", "0", "1", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(8, "ah", "", "1", "0", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(8, "ah", "", "0", "0", "cmp", "je", "jne"), # ZF=1

    FlagTestCase(8, "al", "", "1", "1", "cmp", "je", "jne"), # ZF=1
    FlagTestCase(8, "al", "", "0", "1", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(8, "al", "", "1", "0", "cmp", "jne", "je"), # ZF=0
    FlagTestCase(8, "al", "", "0", "0", "cmp", "je", "jne"), # ZF=1

    # TEST
    FlagTestCase(64, "rax", "", "1", "0", "test", "je", "jne"), # ZF=1
    FlagTestCase(64, "rax", "", "1", "1", "test", "jne", "je"), # ZF=0
    FlagTestCase(64, "rax", "", "0", "1", "test", "je", "jne"), # ZF=1

    FlagTestCase(32, "eax", "", "1", "0", "test", "je", "jne"), # ZF=1
    FlagTestCase(32, "eax", "", "1", "1", "test", "jne", "je"), # ZF=0
    FlagTestCase(32, "eax", "", "0", "1", "test", "je", "jne"), # ZF=1

    FlagTestCase(16, "ax", "", "1", "0", "test", "je", "jne"), # ZF=1
    FlagTestCase(16, "ax", "", "1", "1", "test", "jne", "je"), # ZF=0
    FlagTestCase(16, "ax", "", "0", "1", "test", "je", "jne"), # ZF=1

    FlagTestCase(8, "ah", "", "1", "0", "test", "je", "jne"), # ZF=1
    FlagTestCase(8, "ah", "", "1", "1", "test", "jne", "je"), # ZF=0
    FlagTestCase(8, "ah", "", "0", "1", "test", "je", "jne"), # ZF=1

    FlagTestCase(8, "al", "", "1", "0", "test", "je", "jne"), # ZF=1
    FlagTestCase(8, "al", "", "1", "1", "test", "jne", "je"), # ZF=0
    FlagTestCase(8, "al", "", "0", "1", "test", "je", "jne"), # ZF=1
]

SUITES = {
    "ZF" : ZERO_TESTS,
    "SF" : SIGN_TESTS,
    "CF" : CARRY_TESTS,
    "OF" : OVERFLOW_TESTS,
    "ABOVE" : ABOVE_TESTS,
    "GREATER_EQ" : GREATER_EQ_TESTS,
    "GREATER" : GREATER_TESTS,
    "ALU" : ALU_TESTS,
    "LOAD" : LOAD_TESTS,
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
            test.f_genstrs(test, n, f)
            n = n + 1

    f.write(".text\n")
    f.write(".type _start, @function\n")
    f.write(".global _start\n")
    f.write("_start:\n")

    # Generate tests
    n = 0
    for suite in suites:
        for test in suite:
            test.f_gentest(test, n, f)
            n = n + 1

    # Write epilog
    f.write(ASM_EPILOG)

    f.write(".size _start, .-_start\n")


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
