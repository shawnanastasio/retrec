section .data
    JUMP_1_STR: db 'Jump 1 taken', 10
    JUMP_1_STR_LEN: equ $-JUMP_1_STR
    JUMP_2_STR: db 'Jump 2 taken', 10
    JUMP_2_STR_LEN: equ $-JUMP_2_STR

section .text

global _start
_start:
    jmp 1f
..@j2:
    mov rax, 1 ; SYS_write
    mov rdi, 1
    mov rsi, JUMP_2_STR
    mov edx, JUMP_2_STR_LEN
    syscall
    jmp ..@exit

1:
    mov rax, 1 ; SYS_write
    mov rdi, 1
    mov rsi, JUMP_1_STR
    mov edx, JUMP_1_STR_LEN
    syscall
    jmp ..@j2

..@exit:
    mov rax, 60 ; SYS_exit
    mov rdi, 0
    syscall
