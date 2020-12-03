.intel_syntax noprefix

.data
    PASS_STR: .ascii "PASS"

    DISP_STR: .ascii    "FAIL: DISP Load/Store\n"
    DISP_STR_LEN = . - DISP_STR

    BASE_STR: .ascii    "FAIL: BASE Load/Store\n"
    BASE_STR_LEN = . - BASE_STR

    BASE_IDX_STR: .ascii    "FAIL: BASE_IDX Load/Store\n"
    BASE_IDX_STR_LEN = . - BASE_IDX_STR

    BASE_IDX_DISP_STR: .ascii    "FAIL: BASE_IDX_DISP Load/Store\n"
    BASE_IDX_DISP_STR_LEN = . - BASE_IDX_DISP_STR

    BASE_IDX_SCALE_STR: .ascii    "FAIL: BASE_IDX_SCALE Load/Store\n"
    BASE_IDX_SCALE_STR_LEN = . - BASE_IDX_SCALE_STR

    IDX_SCALE_DISP_STR: .ascii    "FAIL: IDX_SCALE_DISP Load/Store\n"
    IDX_SCALE_DISP_STR_LEN = . - IDX_SCALE_DISP_STR

    BASE_IDX_SCALE_DISP_STR: .ascii    "FAIL: BASE_IDX_SCALE_DISP Load/Store\n"
    BASE_IDX_SCALE_DISP_STR_LEN = . - BASE_IDX_SCALE_DISP_STR

    RIPREL_STR: .ascii    "FAIL: RIPREL Load/Store\n"
    RIPREL_STR_LEN = . - RIPREL_STR

.text

.global _start
_start:
    # Displacement
    mov eax, dword ptr [PASS_STR]
    mov dword ptr [DISP_STR], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET DISP_STR
    mov edx, DISP_STR_LEN
    syscall

    # Base
    mov eax, OFFSET PASS_STR
    mov eax, [eax]
    mov ebx, OFFSET BASE_STR
    mov [ebx], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET BASE_STR
    mov edx, BASE_STR_LEN
    syscall

    # Base+Index
    mov eax, OFFSET PASS_STR-8
    mov ecx, OFFSET 8
    mov eax, [eax+ecx]

    mov ebx, OFFSET BASE_IDX_STR-8
    mov [ebx + ecx], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET BASE_IDX_STR
    mov edx, BASE_IDX_STR_LEN
    syscall

    # Base+Index+Displacement
    mov eax, OFFSET PASS_STR-12
    mov ecx, OFFSET 8
    mov eax, [eax + ecx + 4]

    mov ebx, OFFSET BASE_IDX_DISP_STR-12
    mov [ebx + ecx + 4], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET BASE_IDX_DISP_STR
    mov edx, BASE_IDX_DISP_STR_LEN
    syscall

    # Base+Index*Scale
    mov eax, OFFSET PASS_STR-8
    mov ecx, OFFSET 4
    mov eax, [eax + ecx*2]

    mov ebx, OFFSET BASE_IDX_SCALE_STR-8
    mov [ebx + ecx*2], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET BASE_IDX_SCALE_STR
    mov edx, BASE_IDX_SCALE_STR_LEN
    syscall

    # Index*Scale+Displacement
    mov eax, OFFSET PASS_STR
    mov eax, [eax*2 - 0x421018] # 0x421018 - address of PASS_STR

    mov ebx, OFFSET IDX_SCALE_DISP_STR
    mov [ebx*2 - 0x4210a1], eax # 0x4210a1 - address of IDX_SCALE_DISP_STR

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET IDX_SCALE_DISP_STR
    mov edx, IDX_SCALE_DISP_STR_LEN
    syscall

    # Base + Index*Scale + Displacement
    mov eax, OFFSET PASS_STR - 9
    mov ecx, 4
    mov eax, [eax + ecx*2 + 1]

    mov ebx, OFFSET BASE_IDX_SCALE_DISP_STR - 9
    mov [ebx + ecx*2 + 1], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET BASE_IDX_SCALE_DISP_STR
    mov edx, BASE_IDX_SCALE_DISP_STR_LEN
    syscall

    # RIP-relative
    mov eax, dword ptr [rip + PASS_STR@GOTPCREL]
    mov eax, [eax]

    mov ebx, [rip + RIPREL_STR@GOTPCREL]
    mov [ebx], eax

    mov rax, 1 # SYS_write
    mov rdi, 1
    mov rsi, OFFSET RIPREL_STR
    mov edx, RIPREL_STR_LEN
    syscall

    # Exit
    mov rax, 60 # SYS_exit
    mov rdi, 0
    syscall
