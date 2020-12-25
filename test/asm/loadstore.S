.intel_syntax noprefix

.data
    BYTE_STR: .ascii    "PASS: BYTE memcpy worked!\n"
    BYTE_STR_LEN = . - BYTE_STR

    WORD_STR: .ascii    "PASS: WORD memcpy worked!\n"
    WORD_STR_LEN = . - WORD_STR # 26

    DWORD_STR: .ascii    "PASS: DWORD memcpy worked!!\n"
    DWORD_STR_LEN = . - DWORD_STR # 28

    QWORD_STR: .ascii    "PASS: QWORD memcpy worked....!!\n"
    QWORD_STR_LEN = . - QWORD_STR # 32

    ALIAS_PASS_STR: .ascii "PASS: Load to aliased register (ah) worked!\n"
    ALIAS_PASS_STR_LEN = . - ALIAS_PASS_STR
    ALIAS_FAIL_STR: .ascii "FAIL: Load to ailased register (ah) failed!\n"
    ALIAS_FAIL_STR_LEN = . - ALIAS_FAIL_STR

    ALIAS2_PASS_STR: .ascii "PASS: Load to aliased register (al) worked!\n"
    ALIAS2_PASS_STR_LEN = . - ALIAS2_PASS_STR
    ALIAS2_FAIL_STR: .ascii "FAIL: Load to ailased register (al) failed!\n"
    ALIAS2_FAIL_STR_LEN = . - ALIAS2_FAIL_STR

    ALIAS3_PASS_STR: .ascii "PASS: Load to aliased register (ax) worked!\n"
    ALIAS3_PASS_STR_LEN = . - ALIAS3_PASS_STR
    ALIAS3_FAIL_STR: .ascii "FAIL: Load to ailased register (ax) failed!\n"
    ALIAS3_FAIL_STR_LEN = . - ALIAS3_FAIL_STR

    .lcomm buf, 1024
    zero_byte: .byte 0
    zero_word: .word 0
.text

.global _start
_start:
    # Copy BYTE_STR one byte at a time
    mov rax, OFFSET BYTE_STR
    mov rbx, 0
    mov rcx, OFFSET buf
0:
    cmp rbx, BYTE_STR_LEN
    jge 1f

    lea rdx, BYTE PTR[rax+rbx]
    mov dh, BYTE PTR[rdx]
    mov BYTE PTR[rcx+rbx], dh
    inc rbx

    jmp 0b

1: # Done copying BYTE_STR
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET buf
    mov edx, BYTE_STR_LEN
    syscall
    
# Copy WORD_STR one word at a time
    mov rax, OFFSET WORD_STR
    mov rbx, 0
    mov rcx, OFFSET buf
0:
    cmp rbx, WORD_STR_LEN/2
    jge 1f

    mov dx, WORD PTR[rax+rbx*2]
    mov WORD PTR[rcx+rbx*2], dx
    inc rbx

    jmp 0b
1: # Done copying WORD_STR
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET buf
    mov edx, WORD_STR_LEN
    syscall

# Copy DWORD_STR one dword at a time
    mov rax, OFFSET DWORD_STR
    mov rbx, 0
    mov rcx, OFFSET buf
0:
    cmp rbx, DWORD_STR_LEN/4
    jge 1f

    mov edx, DWORD PTR[rax+rbx*4]
    mov DWORD PTR[rcx+rbx*4], edx
    inc rbx

    jmp 0b
1: # Done copying DWORD_STR
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET buf
    mov edx, DWORD_STR_LEN
    syscall

# Copy QWORD_STR one dword at a time
    mov rax, OFFSET QWORD_STR
    mov rbx, 0
    mov rcx, OFFSET buf
0:
    cmp rbx, QWORD_STR_LEN/8
    jge 1f

    mov rdx, QWORD PTR[rax+rbx*8]
    mov QWORD PTR[rcx+rbx*8], rdx
    inc rbx

    jmp 0b
1: # Done copying QWORD_STR
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET buf
    mov edx, QWORD_STR_LEN
    syscall

# Confirm loads of aliased registers work
    mov rax, -1
    mov ah, [zero_byte]
    mov rbx, 0xFFFFFFFFFFFF00FF
    cmp rax, rbx
    jne 1f

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET ALIAS_PASS_STR
    mov edx, ALIAS_PASS_STR_LEN
    syscall
    jmp 10f

1: #fail
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET ALIAS_FAIL_STR
    mov edx, ALIAS_FAIL_STR_LEN
    syscall

10:
    mov rax, -1
    mov al, [zero_byte]
    mov rbx, 0xFFFFFFFFFFFFFF00
    cmp rax, rbx
    jne 1f

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET ALIAS2_PASS_STR
    mov edx, ALIAS2_PASS_STR_LEN
    syscall
    jmp 10f

1: #fail
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET ALIAS2_FAIL_STR
    mov edx, ALIAS2_FAIL_STR_LEN
    syscall

10:
    mov rax, -1
    mov ax, [zero_word]
    mov rbx, 0xFFFFFFFFFFFF0000
    cmp rax, rbx
    jne 1f

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET ALIAS3_PASS_STR
    mov edx, ALIAS3_PASS_STR_LEN
    syscall
    jmp 10f

1: #fail
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET ALIAS3_FAIL_STR
    mov edx, ALIAS3_FAIL_STR_LEN
    syscall

10:
99:
    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
.size _start, .-_start
