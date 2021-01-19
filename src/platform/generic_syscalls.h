/**
 * Copyright 2020-2021 Shawn Anastasio.
 *
 * This file is part of retrec.
 *
 * retrec is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * retrec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with retrec.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <platform/syscall_types.h>
#include <util/magic.h>
#include <util/staticvector.h>

#include <variant>

#include <cstdint>
#include <cstddef>

namespace retrec {

constexpr size_t SYSCALL_MAX_ARG_COUNT = 6;

#define ENUMERATE_GENERIC_LINUX_SYSCALLS(x) \
    x(read, 0) \
    x(write, 1) \
    x(open, 2) \
    x(close, 3) \
    x(stat, 4) \
    x(fstat, 5) \
    x(lstat, 6) \
    x(poll, 7) \
    x(lseek, 8) \
    x(mmap, 9) \
    x(mprotect, 10) \
    x(munmap, 11) \
    x(brk, 12) \
    x(rt_sigaction, 13) \
    x(rt_sigprocmask, 14) \
    x(rt_sigreturn, 15) \
    x(ioctl, 16) \
    x(pread64, 17) \
    x(pwrite64, 18) \
    x(readv, 19) \
    x(writev, 20) \
    x(access, 21) \
    x(pipe, 22) \
    x(select, 23) \
    x(sched_yield, 24) \
    x(mremap, 25) \
    x(msync, 26) \
    x(mincore, 27) \
    x(madvise, 28) \
    x(shmget, 29) \
    x(shmat, 30) \
    x(shmctl, 31) \
    x(dup, 32) \
    x(dup2, 33) \
    x(pause, 34) \
    x(nanosleep, 35) \
    x(getitimer, 36) \
    x(alarm, 37) \
    x(setitimer, 38) \
    x(getpid, 39) \
    x(sendfile, 40) \
    x(socket, 41) \
    x(connect, 42) \
    x(accept, 43) \
    x(sendto, 44) \
    x(recvfrom, 45) \
    x(sendmsg, 46) \
    x(recvmsg, 47) \
    x(shutdown, 48) \
    x(bind, 49) \
    x(listen, 50) \
    x(getsockname, 51) \
    x(getpeername, 52) \
    x(socketpair, 53) \
    x(setsockopt, 54) \
    x(getsockopt, 55) \
    x(clone, 56) \
    x(fork, 57) \
    x(vfork, 58) \
    x(execve, 59) \
    x(exit, 60) \
    x(wait4, 61) \
    x(kill, 62) \
    x(uname, 63) \
    x(semget, 64) \
    x(semop, 65) \
    x(semctl, 66) \
    x(shmdt, 67) \
    x(msgget, 68) \
    x(msgsnd, 69) \
    x(msgrcv, 70) \
    x(msgctl, 71) \
    x(fcntl, 72) \
    x(flock, 73) \
    x(fsync, 74) \
    x(fdatasync, 75) \
    x(truncate, 76) \
    x(ftruncate, 77) \
    x(getdents, 78) \
    x(getcwd, 79) \
    x(chdir, 80) \
    x(fchdir, 81) \
    x(rename, 82) \
    x(mkdir, 83) \
    x(rmdir, 84) \
    x(creat, 85) \
    x(link, 86) \
    x(unlink, 87) \
    x(symlink, 88) \
    x(readlink, 89) \
    x(chmod, 90) \
    x(fchmod, 91) \
    x(chown, 92) \
    x(fchown, 93) \
    x(lchown, 94) \
    x(umask, 95) \
    x(gettimeofday, 96) \
    x(getrlimit, 97) \
    x(getrusage, 98) \
    x(sysinfo, 99) \
    x(times, 100) \
    x(ptrace, 101) \
    x(getuid, 102) \
    x(syslog, 103) \
    x(getgid, 104) \
    x(setuid, 105) \
    x(setgid, 106) \
    x(geteuid, 107) \
    x(getegid, 108) \
    x(setpgid, 109) \
    x(getppid, 110) \
    x(getpgrp, 111) \
    x(setsid, 112) \
    x(setreuid, 113) \
    x(setregid, 114) \
    x(getgroups, 115) \
    x(setgroups, 116) \
    x(setresuid, 117) \
    x(getresuid, 118) \
    x(setresgid, 119) \
    x(getresgid, 120) \
    x(getpgid, 121) \
    x(setfsuid, 122) \
    x(setfsgid, 123) \
    x(getsid, 124) \
    x(capget, 125) \
    x(capset, 126) \
    x(rt_sigpending, 127) \
    x(rt_sigtimedwait, 128) \
    x(rt_sigqueueinfo, 129) \
    x(rt_sigsuspend, 130) \
    x(sigaltstack, 131) \
    x(utime, 132) \
    x(mknod, 133) \
    x(uselib, 134) \
    x(personality, 135) \
    x(ustat, 136) \
    x(statfs, 137) \
    x(fstatfs, 138) \
    x(sysfs, 139) \
    x(getpriority, 140) \
    x(setpriority, 141) \
    x(sched_setparam, 142) \
    x(sched_getparam, 143) \
    x(sched_setscheduler, 144) \
    x(sched_getscheduler, 145) \
    x(sched_get_priority_max, 146) \
    x(sched_get_priority_min, 147) \
    x(sched_rr_get_interval, 148) \
    x(mlock, 149) \
    x(munlock, 150) \
    x(mlockall, 151) \
    x(munlockall, 152) \
    x(vhangup, 153) \
    x(modify_ldt, 154) \
    x(pivot_root, 155) \
    x(_sysctl, 156) \
    x(prctl, 157) \
    x(arch_prctl, 158) \
    x(adjtimex, 159) \
    x(setrlimit, 160) \
    x(chroot, 161) \
    x(sync, 162) \
    x(acct, 163) \
    x(settimeofday, 164) \
    x(mount, 165) \
    x(umount2, 166) \
    x(swapon, 167) \
    x(swapoff, 168) \
    x(reboot, 169) \
    x(sethostname, 170) \
    x(setdomainname, 171) \
    x(iopl, 172) \
    x(ioperm, 173) \
    x(create_module, 174) \
    x(init_module, 175) \
    x(delete_module, 176) \
    x(get_kernel_syms, 177) \
    x(query_module, 178) \
    x(quotactl, 179) \
    x(nfsservctl, 180) \
    x(getpmsg, 181) \
    x(putpmsg, 182) \
    x(afs_syscall, 183) \
    x(tuxcall, 184) \
    x(security, 185) \
    x(gettid, 186) \
    x(readahead, 187) \
    x(setxattr, 188) \
    x(lsetxattr, 189) \
    x(fsetxattr, 190) \
    x(getxattr, 191) \
    x(lgetxattr, 192) \
    x(fgetxattr, 193) \
    x(listxattr, 194) \
    x(llistxattr, 195) \
    x(flistxattr, 196) \
    x(removexattr, 197) \
    x(lremovexattr, 198) \
    x(fremovexattr, 199) \
    x(tkill, 200) \
    x(time, 201) \
    x(futex, 202) \
    x(sched_setaffinity, 203) \
    x(sched_getaffinity, 204) \
    x(set_thread_area, 205) \
    x(io_setup, 206) \
    x(io_destroy, 207) \
    x(io_getevents, 208) \
    x(io_submit, 209) \
    x(io_cancel, 210) \
    x(get_thread_area, 211) \
    x(lookup_dcookie, 212) \
    x(epoll_create, 213) \
    x(epoll_ctl_old, 214) \
    x(epoll_wait_old, 215) \
    x(remap_file_pages, 216) \
    x(getdents64, 217) \
    x(set_tid_address, 218) \
    x(restart_syscall, 219) \
    x(semtimedop, 220) \
    x(fadvise64, 221) \
    x(timer_create, 222) \
    x(timer_settime, 223) \
    x(timer_gettime, 224) \
    x(timer_getoverrun, 225) \
    x(timer_delete, 226) \
    x(clock_settime, 227) \
    x(clock_gettime, 228) \
    x(clock_getres, 229) \
    x(clock_nanosleep, 230) \
    x(exit_group, 231) \
    x(epoll_wait, 232) \
    x(epoll_ctl, 233) \
    x(tgkill, 234) \
    x(utimes, 235) \
    x(vserver, 236) \
    x(mbind, 237) \
    x(set_mempolicy, 238) \
    x(get_mempolicy, 239) \
    x(mq_open, 240) \
    x(mq_unlink, 241) \
    x(mq_timedsend, 242) \
    x(mq_timedreceive, 243) \
    x(mq_notify, 244) \
    x(mq_getsetattr, 245) \
    x(kexec_load, 246) \
    x(waitid, 247) \
    x(add_key, 248) \
    x(request_key, 249) \
    x(keyctl, 250) \
    x(ioprio_set, 251) \
    x(ioprio_get, 252) \
    x(inotify_init, 253) \
    x(inotify_add_watch, 254) \
    x(inotify_rm_watch, 255) \
    x(migrate_pages, 256) \
    x(openat, 257) \
    x(mkdirat, 258) \
    x(mknodat, 259) \
    x(fchownat, 260) \
    x(futimesat, 261) \
    x(newfstatat, 262) \
    x(unlinkat, 263) \
    x(renameat, 264) \
    x(linkat, 265) \
    x(symlinkat, 266) \
    x(readlinkat, 267) \
    x(fchmodat, 268) \
    x(faccessat, 269) \
    x(pselect6, 270) \
    x(ppoll, 271) \
    x(unshare, 272) \
    x(set_robust_list, 273) \
    x(get_robust_list, 274) \
    x(splice, 275) \
    x(tee, 276) \
    x(sync_file_range, 277) \
    x(vmsplice, 278) \
    x(move_pages, 279) \
    x(utimensat, 280) \
    x(epoll_pwait, 281) \
    x(signalfd, 282) \
    x(timerfd_create, 283) \
    x(eventfd, 284) \
    x(fallocate, 285) \
    x(timerfd_settime, 286) \
    x(timerfd_gettime, 287) \
    x(accept4, 288) \
    x(signalfd4, 289) \
    x(eventfd2, 290) \
    x(epoll_create1, 291) \
    x(dup3, 292) \
    x(pipe2, 293) \
    x(inotify_init1, 294) \
    x(preadv, 295) \
    x(pwritev, 296) \
    x(rt_tgsigqueueinfo, 297) \
    x(perf_event_open, 298) \
    x(recvmmsg, 299) \
    x(fanotify_init, 300) \
    x(fanotify_mark, 301) \
    x(prlimit64, 302) \
    x(name_to_handle_at, 303) \
    x(open_by_handle_at, 304) \
    x(clock_adjtime, 305) \
    x(syncfs, 306) \
    x(sendmmsg, 307) \
    x(setns, 308) \
    x(getcpu, 309) \
    x(process_vm_readv, 310) \
    x(process_vm_writev, 311) \
    x(kcmp, 312) \
    x(finit_module, 313) \
    x(sched_setattr, 314) \
    x(sched_getattr, 315) \
    x(renameat2, 316) \
    x(seccomp, 317) \
    x(getrandom, 318) \
    x(memfd_create, 319) \
    x(kexec_file_load, 320) \
    x(bpf, 321) \
    x(execveat, 322) \
    x(userfaultfd, 323) \
    x(membarrier, 324) \
    x(mlock2, 325) \
    x(copy_file_range, 326) \
    x(preadv2, 327) \
    x(pwritev2, 328) \
    x(pkey_mprotect, 329) \
    x(pkey_alloc, 330) \
    x(pkey_free, 331) \
    x(statx, 332)

// Syscall signatures for common (universally-available) syscalls.
#define ENUMERATE_COMMON_SYSCALL_SIGNATURES(x) \
    x(read, ssize_t, int, void *, size_t) \
    x(write, ssize_t, int, void *, size_t)

// Generic Linux syscall list. Based on X86_64.
enum class SyscallLinuxGeneric : int64_t {
#define declare_enum(name, val) \
    name = val,

    ENUMERATE_GENERIC_LINUX_SYSCALLS(declare_enum)
#undef declare_enum
};

/**
 * Constexpr data structure containing information required to call a syscall:
 *     - Generic syscall number
 *     - Return type
 *     - Argument types
 *     - Argument count
 *
 * Used by syscall translators to validate matching parameter types at compile-time.
 */
template <SyscallLinuxGeneric GenericNumber, typename RetT_, typename... ArgTs>
struct SyscallSignature {
    static constexpr SyscallLinuxGeneric generic_number = GenericNumber;
    using RetT = RetT_;

    template <size_t n>
    using ArgumentTs = typename magic::type_list<ArgTs...>::template type<n>;
    static constexpr size_t arg_count = sizeof...(ArgTs);
};

/**
 * The raw result of a syscall, and whether emulation should halt now.
 */
struct SyscallRet {
    int64_t ret;
    bool should_halt;
};

/**
 * Syscall raw parameter pack.
 */
struct SyscallParameters {
    int64_t args[SYSCALL_MAX_ARG_COUNT];
};

/**
 * Interface for passing syscalls to architecture-specific backends for translation and execution.
 */
class syscall_rewriter {
public:
    virtual std::variant<status_code, SyscallRet> invoke_syscall(int64_t target_number, const SyscallParameters &parameters) = 0;
    virtual ~syscall_rewriter() {}
};


const char *generic_linux_syscall_name(SyscallLinuxGeneric number);

#define ENUMERATE_ALL_LINUX_SYSCALL_DETAILS(x) \
    x(Architecture::X86_64, SyscallDetailsLinuxX86_64) \
    x(Architecture::ppc64le, SyscallDetailsLinuxPPC64LE)

}
