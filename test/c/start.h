// [[noreturn]] _start(void) { exit(main(argc, argv, envp)); }
asm(
    ".intel_syntax noprefix\n"

".global _start\n"
"_start:\n"
    // Load argc, argv, envp
    "mov rdi, [rsp]\n"
    "lea rsi, [rsp + 8]\n"
    "lea rdx, [rsp+rdi*8+16]\n"

    // Call main
    "call main\n"

    // Call exit() with main's result
    "mov rdi, rax\n"
    "mov rax, 60\n" // SYS_exit
    "syscall\n"

    ".att_syntax\n"
);

