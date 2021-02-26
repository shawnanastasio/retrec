.intel_syntax noprefix

.data
    hello_str: .ascii "Hello, world!!!\n"

    .align 16
    .lcomm hello_buf, 16
.text

.align 4
.global _start
_start:
# Test 1: load+store from/to aligned buffer
    mov rdx, OFFSET hello_str
    movapd xmm0, [rdx]
    mov rdx, OFFSET hello_buf
    movapd [rdx], xmm0

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET hello_buf
    mov edx, 16
    syscall

# Test 2: load+store from/to unaligned buffer
    mov rdx, OFFSET hello_str - 1
    movupd xmm0, [rdx + 1]
    mov rdx, OFFSET hello_buf - 1
    movupd [rdx + 1], xmm0

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET hello_buf
    mov edx, 16
    syscall

# Test 3: load+store with intermediate reg-reg mov
    mov rdx, OFFSET hello_str
    movapd xmm0, [rdx]
    movapd xmm1, xmm0
    mov rdx, OFFSET hello_buf
    movapd [rdx], xmm1

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET hello_buf
    mov edx, 16
    syscall

# Test 4: MOVD
    movd xmm0, dword ptr [hello_str]
    movd dword ptr [hello_buf], xmm0
    movd xmm0, dword ptr [hello_str + 4]
    movd dword ptr [hello_buf + 4], xmm0
    movd xmm0, dword ptr [hello_str + 8]
    movd dword ptr [hello_buf + 8], xmm0
    movd xmm0, dword ptr [hello_str + 12]
    movd dword ptr [hello_buf + 12], xmm0

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET hello_buf
    mov edx, 16
    syscall

# exit(0)
    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
