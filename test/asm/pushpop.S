.intel_syntax noprefix

.data
    PUSH_IMM_STR: .ascii    "FAIL: PUSH_IMM!\n"
    PUSH_IMM_STR_LEN = . - PUSH_IMM_STR

    PUSH_REG_STR: .ascii    "FAIL: PUSH_REG!\n"
    PUSH_REG_STR_LEN = . - PUSH_REG_STR

    PUSH_MEM_STR: .ascii    "FAIL: PUSH_MEM!\n"
    PUSH_MEM_STR_LEN = . - PUSH_MEM_STR

    .lcomm tmp, 4

.text

.global _start
_start:
# Push Immediate
    push 0x53534150 # 'PASS'
# Push Register
    mov eax, 0x53534150
    push rax
# Push Memory
    mov dword ptr [tmp], 0x53534150
    push qword ptr [tmp]

# Pop Memory
    pop rax
    mov dword ptr [PUSH_MEM_STR], eax
# Pop Register
    pop rax
    mov dword ptr [PUSH_REG_STR], eax
# Pop Immediate
    pop rax
    mov dword ptr [PUSH_IMM_STR], eax

# Print all
    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET PUSH_IMM_STR
    mov edx, PUSH_IMM_STR_LEN
    syscall

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET PUSH_REG_STR
    mov edx, PUSH_REG_STR_LEN
    syscall

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET PUSH_MEM_STR
    mov edx, PUSH_MEM_STR_LEN
    syscall
   
    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
