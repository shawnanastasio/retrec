.intel_syntax noprefix

.data
    hello_str: .ascii "Hello, world!!!\n"

    .align 16
    .lcomm hello_buf, 16
.text

.global _start
_start:
    mov rdx, OFFSET hello_str
    movapd xmm0, [rdx]
    mov rdx, OFFSET hello_buf
    movapd [rdx], xmm0

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET hello_buf
    mov edx, 16
    syscall

    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
