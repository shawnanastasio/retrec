.intel_syntax noprefix

.data
    CALL_ADDR_PASS_STR: .ascii "PASS: CALL pushed correct address onto the stack\n"
    CALL_ADDR_PASS_STR_LEN = . - CALL_ADDR_PASS_STR
    CALL_ADDR_FAIL_STR: .ascii "FAIL: CALL pushed wrong address onto the stack\n"
    CALL_ADDR_FAIL_STR_LEN = . - CALL_ADDR_FAIL_STR

    CALL_RET_IMM_PASS_STR: .ascii "PASS: call(imm)+ret executed successfully\n"
    CALL_RET_IMM_PASS_STR_LEN = . - CALL_RET_IMM_PASS_STR
    CALL_RET_IMM_FAIL_STR: .ascii "FAIL: call(imm)+ret executed incorrectly\n"
    CALL_RET_IMM_FAIL_STR_LEN = . - CALL_RET_IMM_FAIL_STR

    CALL_RET_REG_PASS_STR: .ascii "PASS: call(reg)+ret executed successfully\n"
    CALL_RET_REG_PASS_STR_LEN = . - CALL_RET_REG_PASS_STR
    CALL_RET_REG_FAIL_STR: .ascii "FAIL: call(reg)+ret executed incorrectly\n"
    CALL_RET_REG_FAIL_STR_LEN = . - CALL_RET_REG_FAIL_STR

    CALL_RET_IMM_BEFORE_PASS_STR: .ascii "PASS: call(imm)+ret (before) executed successfully\n"
    CALL_RET_IMM_BEFORE_PASS_STR_LEN = . - CALL_RET_IMM_BEFORE_PASS_STR
    CALL_RET_IMM_BEFORE_FAIL_STR: .ascii "FAIL: call(imm)+ret (before) executed incorrectly\n"
    CALL_RET_IMM_BEFORE_FAIL_STR_LEN = . - CALL_RET_IMM_BEFORE_FAIL_STR

    CALL_RET_IMM_GLOBAL_PASS_STR: .ascii "PASS: call(imm)+ret to global function executed successfully\n"
    CALL_RET_IMM_GLOBAL_PASS_STR_LEN = . - CALL_RET_IMM_GLOBAL_PASS_STR
    CALL_RET_IMM_GLOBAL_FAIL_STR: .ascii "FAIL: call(imm)+ret to global function executed incorrectly\n"
    CALL_RET_IMM_GLOBAL_FAIL_STR_LEN = . - CALL_RET_IMM_GLOBAL_FAIL_STR
.text

.type _start, @function
.global _start
_start:
#
#  Test 1: Check return address pushed to stack on CALL
#
    call 1f

    mov rax, 60 # SYS_exit
    mov rdi, 1  # FAIL: Unreachable
    syscall

1:
    # Check whether the return address matches expected
    pop rax
    cmp rax, 0x410005 # expected return address
    je 2f

#no match
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_ADDR_FAIL_STR
    mov edx, CALL_ADDR_FAIL_STR_LEN
    syscall
    jmp 10f

2: #match
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_ADDR_PASS_STR
    mov edx, CALL_ADDR_PASS_STR_LEN
    syscall

#
#  Test 2 : Check CALL (REL_IMM) and RET
#
10:
    mov rax, 0
    call 2f

    cmp rax, 1
    jne 1f

#pass
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_IMM_PASS_STR
    mov edx, CALL_RET_IMM_PASS_STR_LEN
    syscall
    jmp 10f

#fail
1:
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_IMM_FAIL_STR
    mov edx, CALL_RET_IMM_FAIL_STR_LEN
    syscall
    jmp 10f


2: mov rax, 1
    ret
    mov rax, 60 # SYS_exit
    mov rdi, 1
    syscall

#
#  Test 3 : Check CALL (REG) and RET
#
10:
    mov rax, 0
    lea rdi, [rip+2f]
    call rdi

    cmp rax, 1
    jne 1f

#pass
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_REG_PASS_STR
    mov edx, CALL_RET_REG_PASS_STR_LEN
    syscall
    jmp 10f

#fail
1:
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_REG_FAIL_STR
    mov edx, CALL_RET_REG_FAIL_STR_LEN
    syscall
    jmp 10f

2:
    mov rax, 1
    ret

#
# Test 4: Check CALL (IMM) and RET when caller occurs AFTER destination
#
10:
    jmp 2f

1: #destination
    mov rax, 1
    ret

2: #test entry
    mov rax, 0
    call 1b
    cmp rax, 1
    jne 1f

#pass
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_IMM_BEFORE_PASS_STR
    mov edx, CALL_RET_IMM_BEFORE_PASS_STR_LEN
    syscall
    jmp 10f

#fail
1:
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_IMM_BEFORE_FAIL_STR
    mov edx, CALL_RET_IMM_BEFORE_FAIL_STR_LEN
    syscall
#
# Test 5: CALL (IMM) global function
#
10:
    mov rax, 0
    call test5_func
    cmp rax, 1
    jne 1f

#pass
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_IMM_GLOBAL_PASS_STR
    mov edx, CALL_RET_IMM_GLOBAL_PASS_STR_LEN
    syscall
    jmp 10f

#fail
1:
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET CALL_RET_IMM_GLOBAL_FAIL_STR
    mov edx, CALL_RET_IMM_GLOBAL_FAIL_STR_LEN
    syscall

#
# End
#
10:
    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
.size _start, .-_start


#
# Function called by test 5
#
.type test5_func, @function
.global test5_func
test5_func:
    mov rax, 1
    ret
.size test5_func, .-test5_func
