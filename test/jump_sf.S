.intel_syntax noprefix

.data
    TEST_1_STR_PASS: .ascii "PASS: (100-110) -> SF=1\n"
    TEST_1_STR_PASS_LEN = . - TEST_1_STR_PASS
    TEST_1_STR_FAIL: .ascii "FAIL: (100-110) -> SF=0\n"
    TEST_1_STR_FAIL_LEN = . - TEST_1_STR_FAIL

    TEST_2_STR_PASS: .ascii "PASS: (100-99) -> SF=0\n"
    TEST_2_STR_PASS_LEN = . - TEST_2_STR_PASS
    TEST_2_STR_FAIL: .ascii "FAIL: (100-99) -> SF=1\n"
    TEST_2_STR_FAIL_LEN = . - TEST_2_STR_FAIL

.text

.macro print str len
    mov eax, 1 # SYS_write
    mov edi, 1
    mov esi, OFFSET \str
    mov edx, OFFSET \len
    syscall
.endm

.global _start
_start:
0:  # Test 1: !ZF
    mov eax, OFFSET 100
    cmp eax, OFFSET 110
    jns 2f # Bad  - 100-110 > 0
    js 1f  # Good - 100-110 < 0
    jmp 2f # Bad  - Unreachable
1:  # Test 1 PASS
    print TEST_1_STR_PASS, TEST_1_STR_PASS_LEN
    jmp 10f
2:  #Test 1 FAIL
    print TEST_1_STR_FAIL, TEST_1_STR_FAIL_LEN
    jmp 1000f #exit

10: # TEST 2: ZF
    mov eax, OFFSET 100
    cmp eax, 99
    js 2f   # Bad  - 100-99 < 0
    jns 1f  # Good - 100-99 > 0
    jmp 2f  # Bad  - Unreachable
1:  # Test 2 PASS
    print TEST_2_STR_PASS, TEST_2_STR_PASS_LEN
    jmp 20f
2:  #Test 2 FAIL
    print TEST_2_STR_FAIL, TEST_2_STR_FAIL_LEN
    jmp 1000f #exit

20:

1000:
    mov rax, 60 # SYS_exit
    mov edi, 0
    syscall
