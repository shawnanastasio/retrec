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

int main(int argc, char **argv, char **envp) {
    print("Hello from C!\n");
    return 0;
}
