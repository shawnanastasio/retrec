#include "syscall.h"
#include "start.h"

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof(*(x)))

unsigned long strlen(const char *str) {
    unsigned long ret = 0;
    while (*(str++))
        ++ret;
    return ret;
}

void print(const char *str) {
    __syscall4(1 /* sys_write */, 1 /* stdout */, (long)str, strlen(str), 0);
}

char hexchr(unsigned int digit) {
    switch (digit) {
        case 0x0: return '0';
        case 0x1: return '1';
        case 0x2: return '2';
        case 0x3: return '3';
        case 0x4: return '4';
        case 0x5: return '5';
        case 0x6: return '6';
        case 0x7: return '7';
        case 0x8: return '8';
        case 0x9: return '9';
        case 0xA: return 'A';
        case 0xB: return 'B';
        case 0xC: return 'C';
        case 0xD: return 'D';
        case 0xE: return 'E';
        case 0xF: return 'F';
    }
    return '?';
}

char *itoa_hex(unsigned int val, char *out_buf, unsigned long buf_len) {
    // Null terminate buffer
    unsigned long i = buf_len - 1;
    out_buf[i] = '\0';

    // Add digits in reverse
    unsigned int curval = val;
    unsigned int written = 0;
    do {
        unsigned int digit = curval % 16;
        out_buf[--i] = hexchr(digit);
        curval /= 16;
        written++;

        if (!i)
            break;
    } while (curval);

    // Pad to 8 digits
    while (written < 8 && (i - 1)) {
        out_buf[--i] = '0';
        written++;
    }

    return out_buf + i;
}

struct cpuid_result {
    unsigned int eax, ebx, ecx, edx;
};

void get_cpuid(int func, int sub_func, struct cpuid_result *out);
asm(
    ".intel_syntax noprefix\n"

".global get_cpuid\n"
"get_cpuid:\n"
    "push rbx\n"
    "mov eax, edi\n"
    "mov ecx, esi\n"
    "mov r8, rdx\n"
    "cpuid\n"
    "mov dword ptr [r8], eax\n"
    "mov dword ptr [r8 + 4], ebx\n"
    "mov dword ptr [r8 + 8], ecx\n"
    "mov dword ptr [r8 + 12], edx\n"
    "pop rbx\n"
    "ret\n"

    ".att_syntax\n"
);

int main(int argc, char **argv, char **envp) {
#define BUF_SIZE 128
    char buf[255];
    static const struct {
        unsigned int func, sub_func;
    } cpuid_funcs[] = {
        {0x0, 0},
        {0x1, 0},
        {0x2, 0},
        {0x3, 0},
        {0x4, 0},
        {0x4, 1},
        {0x4, 2},
        {0x4, 3},
        {0x4, 4},
        {0x5, 0},
        {0x6, 0},
        {0x7, 0},
        {0x7, 1},
        {0x7, 2},
        {0x7, 3},
        {0x7, 4},
        {0x9, 0},
        {0xA, 0},
        {0xB, 0},
        {0xD, 0},
        {0xD, 1},
        {0xD, 2},
        {0xD, 3},
        {0xD, 4},
        {0xF, 0},
        {0xF, 1},
        {0x10, 0},
        {0x10, 1},
        {0x10, 2},
        {0x12, 0},
        {0x12, 1},
        {0x12, 2},
        {0x14, 0},
        {0x14, 1},
        {0x15, 0},
        {0x16, 0},
        {0x17, 0},
        {0x17, 1},
        {0x17, 2},
        {0x17, 3},
        {0x80000000, 0},
        {0x80000001, 0},
        {0x80000002, 0},
        {0x80000003, 0},
        {0x80000004, 0},
        {0x80000005, 0},
        {0x80000006, 0},
        {0x80000007, 0},
        {0x80000008, 0},
    };

    for (int i = 0; i < ARRAY_SIZE(cpuid_funcs); i++) {
        struct cpuid_result result;
        get_cpuid(cpuid_funcs[i].func, cpuid_funcs[i].sub_func, &result);

        print("CPUID(");
        print(itoa_hex(cpuid_funcs[i].func, buf, BUF_SIZE));
        print(", ");
        print(itoa_hex(cpuid_funcs[i].sub_func, buf, BUF_SIZE));
        print(")\n");

        print("eax=");
        print(itoa_hex(result.eax, buf, BUF_SIZE));
        print("\n");

        print("ebx=");
        print(itoa_hex(result.ebx, buf, BUF_SIZE));
        print("\n");

        print("ecx=");
        print(itoa_hex(result.ecx, buf, BUF_SIZE));
        print("\n");

        print("edx=");
        print(itoa_hex(result.edx, buf, BUF_SIZE));
        print("\n\n");
    }

    return 0;
}
