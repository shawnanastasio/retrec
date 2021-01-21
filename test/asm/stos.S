.intel_syntax noprefix

.data
    STOSB_EDI_STR: .ascii    "STOSB_EDI:      should be '11': 00\n"
    STOSB_EDI_STR_LEN = . - STOSB_EDI_STR

    STOSB_FORWARD_STR: .ascii    "STOSB_FORWARD:  should be '11': 00\n"
    STOSB_FORWARD_STR_LEN = . - STOSB_FORWARD_STR
    STOSB_BACKWARD_STR: .ascii    "STOSB_BACKWARD: should be '11': 00\n"
    STOSB_BACKWARD_STR_LEN = . - STOSB_BACKWARD_STR

    STOSW_FORWARD_STR: .ascii    "STOSW_FORWARD:  should be '1111': 0000\n"
    STOSW_FORWARD_STR_LEN = . - STOSW_FORWARD_STR
    STOSW_BACKWARD_STR: .ascii    "STOSW_BACKWARD: should be '1111': 0000\n"
    STOSW_BACKWARD_STR_LEN = . - STOSW_BACKWARD_STR

    STOSD_FORWARD_STR: .ascii    "STOSD_FORWARD:  should be '11111111': 00000000\n"
    STOSD_FORWARD_STR_LEN = . - STOSD_FORWARD_STR
    STOSD_BACKWARD_STR: .ascii    "STOSD_BACKWARD: should be '11111111': 00000000\n"
    STOSD_BACKWARD_STR_LEN = . - STOSD_BACKWARD_STR

    STOSQ_FORWARD_STR: .ascii    "STOSQ_FORWARD:  should be '1111111111111111': 0000000000000000\n"
    STOSQ_FORWARD_STR_LEN = . - STOSQ_FORWARD_STR
    STOSQ_BACKWARD_STR: .ascii    "STOSQ_BACKWARD: should be '1111111111111111': 0000000000000000\n"
    STOSQ_BACKWARD_STR_LEN = . - STOSQ_BACKWARD_STR
.text

.global _start
_start:
# STOSB, DF=0, edi
    cld # clear direction flag

    mov rdi, OFFSET STOSB_EDI_STR + STOSB_EDI_STR_LEN - 3
    mov al, 0x31 # ASCII '1'
    mov r9, 0x8000000000000000
    or rdi, r9
    stosb [edi]
    stosb [edi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSB_EDI_STR
    mov edx, STOSB_EDI_STR_LEN
    syscall

# STOSB, DF=0
    cld # clear direction flag

    mov rdi, OFFSET STOSB_FORWARD_STR + STOSB_FORWARD_STR_LEN - 3
    mov al, 0x31 # ASCII '1'
    stosb [rdi]
    stosb [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSB_FORWARD_STR
    mov edx, STOSB_FORWARD_STR_LEN
    syscall

#STOSB, DF=1
    std # set direction flag

    mov rdi, OFFSET STOSB_BACKWARD_STR + STOSB_BACKWARD_STR_LEN - 2
    mov al, 0x31 # ASCII '1'
    stosb [rdi]
    stosb [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSB_BACKWARD_STR
    mov edx, STOSB_BACKWARD_STR_LEN
    syscall

# STOSW, DF=0
    cld # clear direction flag

    mov rdi, OFFSET STOSW_FORWARD_STR + STOSW_FORWARD_STR_LEN - 5
    mov ax, 0x3131 # ASCII '11'
    stosw [rdi]
    stosw [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSW_FORWARD_STR
    mov edx, STOSW_FORWARD_STR_LEN
    syscall

#STOSW, DF=1
    std # set direction flag

    mov rdi, OFFSET STOSW_BACKWARD_STR + STOSW_BACKWARD_STR_LEN - 3
    mov ax, 0x3131 # ASCII '11'
    stosw [rdi]
    stosw [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSW_BACKWARD_STR
    mov edx, STOSW_BACKWARD_STR_LEN
    syscall

# STOSD, DF=0
    cld # clear direction flag

    mov rdi, OFFSET STOSD_FORWARD_STR + STOSD_FORWARD_STR_LEN - 9
    mov eax, 0x31313131 # ASCII '1111'
    stosd [rdi]
    stosd [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSD_FORWARD_STR
    mov edx, STOSD_FORWARD_STR_LEN
    syscall

#STOSD, DF=1
    std # set direction flag

    mov rdi, OFFSET STOSD_BACKWARD_STR + STOSD_BACKWARD_STR_LEN - 5
    mov eax, 0x31313131 # ASCII '1111'
    stosd [rdi]
    stosd [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSD_BACKWARD_STR
    mov edx, STOSD_BACKWARD_STR_LEN
    syscall

# STOSQ, DF=0
    cld # clear direction flag

    mov rdi, OFFSET STOSQ_FORWARD_STR + STOSQ_FORWARD_STR_LEN - 17
    mov rax, 0x3131313131313131 # ASCII '11111111'
    stosq [rdi]
    stosq [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSQ_FORWARD_STR
    mov edx, STOSQ_FORWARD_STR_LEN
    syscall

#STOSQ, DF=1
    std # set direction flag

    mov rdi, OFFSET STOSQ_BACKWARD_STR + STOSQ_BACKWARD_STR_LEN - 9
    mov rax, 0x3131313131313131 # ASCII '11111111'
    stosq [rdi]
    stosq [rdi]

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET STOSQ_BACKWARD_STR
    mov edx, STOSQ_BACKWARD_STR_LEN
    syscall

#exit
    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
