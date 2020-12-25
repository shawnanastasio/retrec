
.intel_syntax noprefix

.macro print str len
    mov eax, 1 # SYS_write
    mov edi, 1
    mov esi, OFFSET \str
    mov edx, OFFSET \len
    syscall
.endm

.data
    TEST_0_STR_PASS: .ascii "PASS: (cmp (u16)0x7FFF, (u16)-1) -> jo\n"
    TEST_0_STR_PASS_LEN = . - TEST_0_STR_PASS
    TEST_0_STR_FAIL: .ascii "FAIL: (cmp (u16)0x7FFF, (u16)-1) -> jno\n"
    TEST_0_STR_FAIL_LEN = . - TEST_0_STR_FAIL
    TEST_0_STR_UNREACHABLE: .ascii "FAIL: (cmp (u16)0x7FFF, (u16)-1) -> UNREACHABLE!\n"
    TEST_0_STR_UNREACHABLE_LEN = . - TEST_0_STR_UNREACHABLE

    TEST_1_STR_PASS: .ascii "PASS: (cmp (u16)0x8000, (u16)1) -> jo\n"
    TEST_1_STR_PASS_LEN = . - TEST_1_STR_PASS
    TEST_1_STR_FAIL: .ascii "FAIL: (cmp (u16)0x8000, (u16)1) -> jno\n"
    TEST_1_STR_FAIL_LEN = . - TEST_1_STR_FAIL
    TEST_1_STR_UNREACHABLE: .ascii "FAIL: (cmp (u16)0x8000, (u16)1) -> UNREACHABLE!\n"
    TEST_1_STR_UNREACHABLE_LEN = . - TEST_1_STR_UNREACHABLE

    TEST_2_STR_PASS: .ascii "PASS: (cmp (u16)0x8000, (u16)1) -> jo\n"
    TEST_2_STR_PASS_LEN = . - TEST_2_STR_PASS
    TEST_2_STR_FAIL: .ascii "FAIL: (cmp (u16)0x8000, (u16)1) -> jno\n"
    TEST_2_STR_FAIL_LEN = . - TEST_2_STR_FAIL
    TEST_2_STR_UNREACHABLE: .ascii "FAIL: (cmp (u16)0x8000, (u16)1) -> UNREACHABLE!\n"
    TEST_2_STR_UNREACHABLE_LEN = . - TEST_2_STR_UNREACHABLE

.text
.global _start
_start:
    mov ax, OFFSET 0x8000
    mov rax, 60 # SYS_exit
    mov edi, 0
    syscall
