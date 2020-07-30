.intel_syntax noprefix

.data
    JUMP_1_STR: .ascii "Jump 1 taken\n"
    JUMP_1_STR_LEN = . - JUMP_1_STR
    JUMP_2_STR: .ascii "Jump 2 taken\n"
    JUMP_2_STR_LEN = . - JUMP_2_STR

.text

.global _start
_start:
    jmp 1f
2:
    mov eax, 1 # SYS_write
    mov edi, 1
    mov esi, OFFSET JUMP_2_STR
    mov edx, JUMP_2_STR_LEN
    syscall
    jmp 3f

1:
    mov eax, 1 # SYS_write
    mov edi, 1
    mov esi, OFFSET JUMP_1_STR
    mov edx, JUMP_1_STR_LEN
    syscall
    jmp 2b

3:
    mov rax, 60 # SYS_exit
    mov edi, 0
    syscall
