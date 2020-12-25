section .data
    HELLO_STR: db 'Hello, World', 10
    HELLO_STR_LEN: equ $-HELLO_STR

section .text

global _start
_start:
    mov rax, 1 ; SYS_write
    mov rdi, 1
    mov rsi, HELLO_STR
    mov edx, HELLO_STR_LEN
    syscall

    mov rax, 60 ; SYS_exit
    mov rdi, 0
    syscall
