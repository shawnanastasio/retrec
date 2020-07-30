.intel_syntax noprefix

.data
msg:
    .ascii    "Hello, world!\n"
    len = . - msg

.text

.global _start
_start:
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET msg
    mov edx, len
    syscall

    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
