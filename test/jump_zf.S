.intel_syntax noprefix

.data
    TEST_1_STR_PASS: .ascii "PASS: (100-10)  -> ZF=0\n"
    TEST_1_STR_PASS_LEN = . - TEST_1_STR_PASS
    TEST_1_STR_FAIL: .ascii "FAIL: (100-10)  -> ZF=1\n"
    TEST_1_STR_FAIL_LEN = . - TEST_1_STR_FAIL

    TEST_2_STR_PASS: .ascii "PASS: (100-100) -> ZF=1\n"
    TEST_2_STR_PASS_LEN = . - TEST_2_STR_PASS
    TEST_2_STR_FAIL: .ascii "FAIL: (100-100) -> ZF=0\n"
    TEST_2_STR_FAIL_LEN = . - TEST_2_STR_FAIL

    TEST_3_STR_PASS: .ascii "PASS: ((u32)0xDEADBEEFCAFEBABA-(u32)0xCAFEBABA) -> ZF=1\n"
    TEST_3_STR_PASS_LEN = . - TEST_3_STR_PASS
    TEST_3_STR_FAIL: .ascii "FAIL: ((u32)0xDEADBEEFCAFEBABA-(u32)0xCAFEBABA) -> ZF=0\n"
    TEST_3_STR_FAIL_LEN = . - TEST_3_STR_FAIL

    TEST_3a_STR_PASS: .ascii "PASS: (0xDEADBEEFCAFEBABA-0xCAFEBABA) -> ZF=0\n"
    TEST_3a_STR_PASS_LEN = . - TEST_3a_STR_PASS
    TEST_3a_STR_FAIL: .ascii "FAIL: (0xDEADBEEFCAFEBABA-0xCAFEBABA) -> ZF=1\n"
    TEST_3a_STR_FAIL_LEN = . - TEST_3a_STR_FAIL

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
0:  # Test 1: !ZF (32-bit)
    mov eax, OFFSET 100
    cmp eax, OFFSET 10
    jz 2f  # Bad  - 100-10 == 0
    jnz 1f # Good - 100-10 != 0
    jmp 2f # Bad  - Unreachable
1:  # Test 1 PASS
    print TEST_1_STR_PASS, TEST_1_STR_PASS_LEN
    jmp 10f
2:  #Test 1 FAIL
    print TEST_1_STR_FAIL, TEST_1_STR_FAIL_LEN
    jmp 1000f #exit

10: # TEST 2: ZF
    mov eax, OFFSET 100
    cmp eax, 100
    jnz 2f  # Bad  - 100-100 != 0
    jz 1f   # Good - 100-100 == 0
    jmp 2f  # Bad  - Unreachable
1:  # Test 2 PASS
    print TEST_2_STR_PASS, TEST_2_STR_PASS_LEN
    jmp 20f
2:  #Test 2 FAIL
    print TEST_2_STR_FAIL, TEST_2_STR_FAIL_LEN
    jmp 1000f #exit


20: # Test 3: !ZF (64-bit vs 32-bit)
    mov rax, OFFSET 0xDEADBEEFCAFEBABA
    mov rbx, OFFSET 0xCAFEBABA
    # for 32-bit, rbx == rax
    # for 64-bit, rax != rbx
    cmp eax, ebx
    jnz 2f # Bad
    jz 1f  # Good
    jmp 2f # Bad
2:
    print TEST_3_STR_FAIL, TEST_3_STR_FAIL_LEN
    jmp 1000f #exit

1: # Now try 64-bit
    cmp rax, rbx
    print TEST_3_STR_PASS, TEST_3_STR_PASS_LEN
    jz 2f  # Bad
    jnz 1f # Good
    jmp 2f # Bad
2:
    print TEST_3a_STR_FAIL, TEST_3a_STR_FAIL_LEN
    jmp 1000f
1:
    print TEST_3a_STR_PASS, TEST_3a_STR_PASS_LEN

1000:
    mov rax, 60 # SYS_exit
    mov edi, 0
    syscall
