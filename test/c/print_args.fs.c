#include "syscall.h"
#include "start.h"

unsigned long strlen(const char *str) {
    unsigned long ret = 0;
    while (*(str++))
        ++ret;
    return ret;
}

void print(const char *str) {
    __syscall3(1 /* sys_write */, 1 /* stdout */, (long)str, strlen(str));
}

char *itoa(int val, char *out_buf, unsigned long out_buf_len) {
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

int main(int argc, char **argv, char **envp) {
    char buf[255];
    print("argc=");
    print(itoa(argc, buf, sizeof(buf)));
    print("\n");

    print("-------\n");
    print("argv:\n");
    while (*argv) {
        print(*(argv++));
        print("\n");
    }
    print("-------\n");

    print("-------\n");
    print("envp:\n");
    while (*envp) {
        print(*(envp++));
        print("\n");
    }
    print("-------\n");

    return 0;
}
