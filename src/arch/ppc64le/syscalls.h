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

#include <util/util.h>
#include <arch/arch.h>
#include <platform/generic_syscalls.h>

#include <cstdint>

namespace retrec {

#define ENUMERATE_PPC64_LINUX_SYSCALLS(x) \
    x(restart_syscall, 0) \
    x(exit, 1) \
    x(fork, 2) \
    x(read, 3) \
    x(write, 4) \
    x(open, 5) \
    x(close, 6) \
    x(waitpid, 7) \
    x(creat, 8) \
    x(link, 9) \
    x(unlink, 10) \
    x(execve, 11) \
    x(chdir, 12) \
    x(time, 13) \
    x(mknod, 14) \
    x(chmod, 15) \
    x(lchown, 16) \
    x(_break, 17) \
    x(oldstat, 18) \
    x(lseek, 19) \
    x(getpid, 20) \
    x(mount, 21) \
    x(umount, 22) \
    x(setuid, 23) \
    x(getuid, 24) \
    x(stime, 25) \
    x(ptrace, 26) \
    x(alarm, 27) \
    x(oldfstat, 28) \
    x(pause, 29) \
    x(utime, 30) \
    x(stty, 31) \
    x(gtty, 32) \
    x(access, 33) \
    x(nice, 34) \
    x(ftime, 35) \
    x(sync, 36) \
    x(kill, 37) \
    x(rename, 38) \
    x(mkdir, 39) \
    x(rmdir, 40) \
    x(dup, 41) \
    x(pipe, 42) \
    x(times, 43) \
    x(prof, 44) \
    x(brk, 45) \
    x(setgid, 46) \
    x(getgid, 47) \
    x(signal, 48) \
    x(geteuid, 49) \
    x(getegid, 50) \
    x(acct, 51) \
    x(umount2, 52) \
    x(lock, 53) \
    x(ioctl, 54) \
    x(fcntl, 55) \
    x(mpx, 56) \
    x(setpgid, 57) \
    x(ulimit, 58) \
    x(oldolduname, 59) \
    x(umask, 60) \
    x(chroot, 61) \
    x(ustat, 62) \
    x(dup2, 63) \
    x(getppid, 64) \
    x(getpgrp, 65) \
    x(setsid, 66) \
    x(sigaction, 67) \
    x(sgetmask, 68) \
    x(ssetmask, 69) \
    x(setreuid, 70) \
    x(setregid, 71) \
    x(sigsuspend, 72) \
    x(sigpending, 73) \
    x(sethostname, 74) \
    x(setrlimit, 75) \
    x(getrlimit, 76) \
    x(getrusage, 77) \
    x(gettimeofday, 78) \
    x(settimeofday, 79) \
    x(getgroups, 80) \
    x(setgroups, 81) \
    x(select, 82) \
    x(symlink, 83) \
    x(oldlstat, 84) \
    x(readlink, 85) \
    x(uselib, 86) \
    x(swapon, 87) \
    x(reboot, 88) \
    x(readdir, 89) \
    x(mmap, 90) \
    x(munmap, 91) \
    x(truncate, 92) \
    x(ftruncate, 93) \
    x(fchmod, 94) \
    x(fchown, 95) \
    x(getpriority, 96) \
    x(setpriority, 97) \
    x(profil, 98) \
    x(statfs, 99) \
    x(fstatfs, 100) \
    x(ioperm, 101) \
    x(socketcall, 102) \
    x(syslog, 103) \
    x(setitimer, 104) \
    x(getitimer, 105) \
    x(stat, 106) \
    x(lstat, 107) \
    x(fstat, 108) \
    x(olduname, 109) \
    x(iopl, 110) \
    x(vhangup, 111) \
    x(idle, 112) \
    x(vm86, 113) \
    x(wait4, 114) \
    x(swapoff, 115) \
    x(sysinfo, 116) \
    x(ipc, 117) \
    x(fsync, 118) \
    x(sigreturn, 119) \
    x(clone, 120) \
    x(setdomainname, 121) \
    x(uname, 122) \
    x(modify_ldt, 123) \
    x(adjtimex, 124) \
    x(mprotect, 125) \
    x(sigprocmask, 126) \
    x(create_module, 127) \
    x(init_module, 128) \
    x(delete_module, 129) \
    x(get_kernel_syms, 130) \
    x(quotactl, 131) \
    x(getpgid, 132) \
    x(fchdir, 133) \
    x(bdflush, 134) \
    x(sysfs, 135) \
    x(personality, 136) \
    x(afs_syscall, 137) \
    x(setfsuid, 138) \
    x(setfsgid, 139) \
    x(_llseek, 140) \
    x(getdents, 141) \
    x(_newselect, 142) \
    x(flock, 143) \
    x(msync, 144) \
    x(readv, 145) \
    x(writev, 146) \
    x(getsid, 147) \
    x(fdatasync, 148) \
    x(_sysctl, 149) \
    x(mlock, 150) \
    x(munlock, 151) \
    x(mlockall, 152) \
    x(munlockall, 153) \
    x(sched_setparam, 154) \
    x(sched_getparam, 155) \
    x(sched_setscheduler, 156) \
    x(sched_getscheduler, 157) \
    x(sched_yield, 158) \
    x(sched_get_priority_max, 159) \
    x(sched_get_priority_min, 160) \
    x(sched_rr_get_interval, 161) \
    x(nanosleep, 162) \
    x(mremap, 163) \
    x(setresuid, 164) \
    x(getresuid, 165) \
    x(query_module, 166) \
    x(poll, 167) \
    x(nfsservctl, 168) \
    x(setresgid, 169) \
    x(getresgid, 170) \
    x(prctl, 171) \
    x(rt_sigreturn, 172) \
    x(rt_sigaction, 173) \
    x(rt_sigprocmask, 174) \
    x(rt_sigpending, 175) \
    x(rt_sigtimedwait, 176) \
    x(rt_sigqueueinfo, 177) \
    x(rt_sigsuspend, 178) \
    x(pread64, 179) \
    x(pwrite64, 180) \
    x(chown, 181) \
    x(getcwd, 182) \
    x(capget, 183) \
    x(capset, 184) \
    x(sigaltstack, 185) \
    x(sendfile, 186) \
    x(getpmsg, 187) \
    x(putpmsg, 188) \
    x(vfork, 189) \
    x(ugetrlimit, 190) \
    x(readahead, 191) \
    x(pciconfig_read, 198) \
    x(pciconfig_write, 199) \
    x(pciconfig_iobase, 200) \
    x(multiplexer, 201) \
    x(getdents64, 202) \
    x(pivot_root, 203) \
    x(madvise, 205) \
    x(mincore, 206) \
    x(gettid, 207) \
    x(tkill, 208) \
    x(setxattr, 209) \
    x(lsetxattr, 210) \
    x(fsetxattr, 211) \
    x(getxattr, 212) \
    x(lgetxattr, 213) \
    x(fgetxattr, 214) \
    x(listxattr, 215) \
    x(llistxattr, 216) \
    x(flistxattr, 217) \
    x(removexattr, 218) \
    x(lremovexattr, 219) \
    x(fremovexattr, 220) \
    x(futex, 221) \
    x(sched_setaffinity, 222) \
    x(sched_getaffinity, 223) \
    x(tuxcall, 225) \
    x(io_setup, 227) \
    x(io_destroy, 228) \
    x(io_getevents, 229) \
    x(io_submit, 230) \
    x(io_cancel, 231) \
    x(set_tid_address, 232) \
    x(fadvise64, 233) \
    x(exit_group, 234) \
    x(lookup_dcookie, 235) \
    x(epoll_create, 236) \
    x(epoll_ctl, 237) \
    x(epoll_wait, 238) \
    x(remap_file_pages, 239) \
    x(timer_create, 240) \
    x(timer_settime, 241) \
    x(timer_gettime, 242) \
    x(timer_getoverrun, 243) \
    x(timer_delete, 244) \
    x(clock_settime, 245) \
    x(clock_gettime, 246) \
    x(clock_getres, 247) \
    x(clock_nanosleep, 248) \
    x(swapcontext, 249) \
    x(tgkill, 250) \
    x(utimes, 251) \
    x(statfs64, 252) \
    x(fstatfs64, 253) \
    x(rtas, 255) \
    x(sys_debug_setcontext, 256) \
    x(migrate_pages, 258) \
    x(mbind, 259) \
    x(get_mempolicy, 260) \
    x(set_mempolicy, 261) \
    x(mq_open, 262) \
    x(mq_unlink, 263) \
    x(mq_timedsend, 264) \
    x(mq_timedreceive, 265) \
    x(mq_notify, 266) \
    x(mq_getsetattr, 267) \
    x(kexec_load, 268) \
    x(add_key, 269) \
    x(request_key, 270) \
    x(keyctl, 271) \
    x(waitid, 272) \
    x(ioprio_set, 273) \
    x(ioprio_get, 274) \
    x(inotify_init, 275) \
    x(inotify_add_watch, 276) \
    x(inotify_rm_watch, 277) \
    x(spu_run, 278) \
    x(spu_create, 279) \
    x(pselect6, 280) \
    x(ppoll, 281) \
    x(unshare, 282) \
    x(splice, 283) \
    x(tee, 284) \
    x(vmsplice, 285) \
    x(openat, 286) \
    x(mkdirat, 287) \
    x(mknodat, 288) \
    x(fchownat, 289) \
    x(futimesat, 290) \
    x(newfstatat, 291) \
    x(unlinkat, 292) \
    x(renameat, 293) \
    x(linkat, 294) \
    x(symlinkat, 295) \
    x(readlinkat, 296) \
    x(fchmodat, 297) \
    x(faccessat, 298) \
    x(get_robust_list, 299) \
    x(set_robust_list, 300) \
    x(move_pages, 301) \
    x(getcpu, 302) \
    x(epoll_pwait, 303) \
    x(utimensat, 304) \
    x(signalfd, 305) \
    x(timerfd_create, 306) \
    x(eventfd, 307) \
    x(sync_file_range2, 308) \
    x(fallocate, 309) \
    x(subpage_prot, 310) \
    x(timerfd_settime, 311) \
    x(timerfd_gettime, 312) \
    x(signalfd4, 313) \
    x(eventfd2, 314) \
    x(epoll_create1, 315) \
    x(dup3, 316) \
    x(pipe2, 317) \
    x(inotify_init1, 318) \
    x(perf_event_open, 319) \
    x(preadv, 320) \
    x(pwritev, 321) \
    x(rt_tgsigqueueinfo, 322) \
    x(fanotify_init, 323) \
    x(fanotify_mark, 324) \
    x(prlimit64, 325) \
    x(socket, 326) \
    x(bind, 327) \
    x(connect, 328) \
    x(listen, 329) \
    x(accept, 330) \
    x(getsockname, 331) \
    x(getpeername, 332) \
    x(socketpair, 333) \
    x(send, 334) \
    x(sendto, 335) \
    x(recv, 336) \
    x(recvfrom, 337) \
    x(shutdown, 338) \
    x(setsockopt, 339) \
    x(getsockopt, 340) \
    x(sendmsg, 341) \
    x(recvmsg, 342) \
    x(recvmmsg, 343) \
    x(accept4, 344) \
    x(name_to_handle_at, 345) \
    x(open_by_handle_at, 346) \
    x(clock_adjtime, 347) \
    x(syncfs, 348) \
    x(sendmmsg, 349) \
    x(setns, 350) \
    x(process_vm_readv, 351) \
    x(process_vm_writev, 352) \
    x(finit_module, 353) \
    x(kcmp, 354) \
    x(sched_setattr, 355) \
    x(sched_getattr, 356) \
    x(renameat2, 357) \
    x(seccomp, 358) \
    x(getrandom, 359) \
    x(memfd_create, 360) \
    x(bpf, 361) \
    x(execveat, 362) \
    x(switch_endian, 363) \
    x(userfaultfd, 364) \
    x(membarrier, 365) \
    x(mlock2, 378) \
    x(copy_file_range, 379) \
    x(preadv2, 380) \
    x(pwritev2, 381) \
    x(kexec_file_load, 382) \
    x(statx, 383) \
    x(pkey_alloc, 384) \
    x(pkey_free, 385) \
    x(pkey_mprotect, 386) \
    x(rseq, 387) \
    x(io_pgetevents, 388) \
    x(semtimedop, 392) \
    x(semget, 393) \
    x(semctl, 394) \
    x(shmget, 395) \
    x(shmctl, 396) \
    x(shmat, 397) \
    x(shmdt, 398) \
    x(msgget, 399) \
    x(msgsnd, 400) \
    x(msgrcv, 401) \
    x(msgctl, 402) \
    x(pidfd_send_signal, 424) \
    x(io_uring_setup, 425) \
    x(io_uring_enter, 426) \
    x(io_uring_register, 427) \
    x(open_tree, 428) \
    x(move_mount, 429) \
    x(fsopen, 430) \
    x(fsconfig, 431) \
    x(fsmount, 432) \
    x(fspick, 433) \
    x(pidfd_open, 434) \
    x(clone3, 435) \
    x(openat2, 437) \
    x(pidfd_getfd, 438) \
    x(faccessat2, 439) \
    x(INVALID, -1)

enum class SyscallLinuxPPC64 : int64_t {
#define declare_enum(name, val) \
    name = val,

    ENUMERATE_PPC64_LINUX_SYSCALLS(declare_enum)
#undef declare_enum
};

struct SyscallDetailsLinuxPPC64LE {
    using SyscallNumberT = SyscallLinuxPPC64;

    //
    // Definitions
    //

    // Define architecture-specific type mappings
#define enumerate_type_mappings(x) \
    x(char,                u8_le)  \
    x(short,               s16_le) \
    x(int,                 s32_le) \
    x(long,                s64_le) \
    x(long long,           s64_le) \
    x(unsigned char,       u8_le)  \
    x(unsigned short,      u16_le) \
    x(unsigned int,        u32_le) \
    x(unsigned long,       u64_le) \
    x(unsigned long long,  u64_le) \
    x(void *,              ptr64)  \
    /* Declare aliases for agnostic types */ \
    ENUMERATE_SYSCALL_ARG_TYPES(x)

    // Define signatures of all supported syscalls
#define enumerate_syscalls(x) \
    /* Enumerate common syscalls first */ \
    ENUMERATE_COMMON_SYSCALL_SIGNATURES(x)

#define access_type_a(a, _) a,
#define access_type_b(_, b) sc_types::b,
    MAGIC_GEN_TYPE_TO_TYPE_LOOKUP(enumerate_type_mappings, arch_types, access_type_a, access_type_b)
#undef access_type_a
#undef access_type_b

#define access_enum(e, ...) SyscallLinuxPPC64::e,
#define access_sig(name, ret, ...) SyscallSignature<SyscallLinuxGeneric::name, ret, ##__VA_ARGS__>,
    MAGIC_GEN_ENUM_TO_TYPE_LOOKUP(enumerate_syscalls, signatures_lut, access_enum, access_sig, SyscallNumberT)
#undef access_enum
#undef access_sig

    //
    // Accessors
    //

    // Accessor for retrieving the signature of a syscall
    template <SyscallNumberT syscall>
    using signature_from_syscall = signatures_lut_look_up_type<syscall>;

    // Accessor for retrieving the corresponding agnostic type for a given archtiecture-specific type
    template <typename T>
    using agnostic_type_from_type = arch_types_look_up_type_b<T>;

#undef enumerate_syscalls
#undef enumerate_type_mappings

};

template <typename TargetDetailsT>
class syscall_rewriter_linux_ppc64le final : public syscall_rewriter {
    SyscallLinuxPPC64 generic_to_native_syscall(int64_t generic_number_);

public:
    using SyscallNumberT = SyscallLinuxPPC64;
    const char *syscall_name(int64_t ppc64le_syscall_number);

    syscall_rewriter_linux_ppc64le();
    ~syscall_rewriter_linux_ppc64le() override;
    std::variant<status_code, SyscallRet> invoke_syscall(int64_t target_number, const SyscallParameters &parameters) override;
};

}
