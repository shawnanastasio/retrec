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

char *itoa64(unsigned long val, char *out_buf, unsigned long out_buf_len) {
    out_buf[out_buf_len-1] = '\0';
    unsigned long i = out_buf_len - 1;
    while (i-- > 0) {
        out_buf[i] = '0' + (val % 10);
        val /= 10;
        if (!val)
            break;
    }
    return out_buf + i;
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

char *itoa64_hex(unsigned long val, char *out_buf, unsigned long buf_len) {
    // Null terminate buffer
    unsigned long i = buf_len - 1;
    out_buf[i] = '\0';

    // Add digits in reverse
    unsigned long curval = val;
    unsigned int written = 0;
    do {
        unsigned int digit = curval % 16;
        out_buf[--i] = hexchr(digit);
        curval /= 16;
        written++;

        if (!i)
            break;
    } while (curval);

    // Pad to 16 digits
    while (written < 16 && (i - 1)) {
        out_buf[--i] = '0';
        written++;
    }

    return out_buf + i;
}


// Lifted from /usr/include/elf.h
typedef struct
{
  unsigned long a_type;		/* Entry type */
  union
    {
      unsigned long a_val;		/* Integer value */
    } a_un;
} Elf64_auxv_t;

int main(int argc, char **argv, char **envp) {
    char buf[256];
    char **auxv_ptr = envp;
    while (*auxv_ptr++); /* increment auxv to end of envp */

    Elf64_auxv_t *auxv;
    for (auxv = (Elf64_auxv_t *)auxv_ptr; auxv->a_type != 0 /* AT_NULL */; auxv++) {
        print("auxv type: ");
        print(itoa64(auxv->a_type, buf, sizeof(buf)));
        print(", value: ");
        switch (auxv->a_type) {
            case 15 /* AT_PLATFORM */:
            case 31 /* AT_EXECFN */:
                print((char *)auxv->a_un.a_val);
                break;
            case 25 /* AT_RANDOM */:
            {
                unsigned long *rand = (void *)auxv->a_un.a_val;
                print(itoa64_hex(rand[0], buf, sizeof(buf)));
                print(itoa64_hex(rand[1], buf, sizeof(buf)));
                break;
            }

            default:
                print(itoa64_hex(auxv->a_un.a_val, buf, sizeof(buf)));
        }
        print("\n");
    }

    return 0;
}
