/**
 * Copyright 2021 Shawn Anastasio.
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

#include <arch/ppc64le/syscalls.h>
#include <arch/x86_64/syscalls.h>

#include <cinttypes>
#include <unistd.h>
#include <sys/types.h>

using namespace retrec;

// Enumerate all syscalls with automatic mappings
#define ENUMERATE_AUTO_SYSCALLS(x) \
    /* First enumerate common syscalls */ \
    ENUMERATE_COMMON_SYSCALL_SIGNATURES(x)

template <typename TargetDetailsT>
syscall_rewriter_linux_ppc64le<TargetDetailsT>::syscall_rewriter_linux_ppc64le() {}

template <typename TargetDetailsT>
syscall_rewriter_linux_ppc64le<TargetDetailsT>::~syscall_rewriter_linux_ppc64le() {}

template <typename TargetDetailsT>
const char *syscall_rewriter_linux_ppc64le<TargetDetailsT>::syscall_name(int64_t ppc64le_syscall_number) {
    SyscallLinuxPPC64 num = (SyscallLinuxPPC64)ppc64le_syscall_number;
    switch (num) {
#define declare_case(name, _) \
        case SyscallLinuxPPC64::name: return #name;

        ENUMERATE_PPC64_LINUX_SYSCALLS(declare_case)
#undef declare_case
        default: UNREACHABLE();
    }
}

template <typename TargetDetailsT, typename TargetSignatureT, typename HostSignatureT, size_t max, size_t n = 0>
void translate_arguments(SyscallParameters &parameters) {
    if constexpr (n < TargetSignatureT::arg_count) {
        // Obtain the type for this parameter as expected by the target and the host
        using TargetT = typename TargetSignatureT::template ArgumentTs<n>;
        using HostT = typename HostSignatureT::template ArgumentTs<n>;
        using AgnosticTargetT = typename TargetDetailsT::template agnostic_type_from_type<TargetT>;
        using AgnosticHostT = typename SyscallDetailsLinuxPPC64LE::template agnostic_type_from_type<HostT>;

        // For now, just make sure that they're the same
        static_assert(std::is_same_v<AgnosticHostT, AgnosticTargetT>, "Unknown translation for syscall argument");

        if constexpr (n < max - 1) {
            return translate_arguments<TargetDetailsT, TargetSignatureT, HostSignatureT, max, n + 1>(parameters);
        }
    }
}

template <typename TargetDetailsT, typename TargetDetailsT::SyscallNumberT target_syscall, SyscallLinuxPPC64 host_syscall>
void validate_and_translate_arguments(SyscallParameters &parameters) {
    // Lookup the signatures for this syscall
    using TargetSignatureT = typename TargetDetailsT::template signature_from_syscall<target_syscall>;
    using HostSignatureT = typename SyscallDetailsLinuxPPC64LE::template signature_from_syscall<host_syscall>;

    // Validate that the signatures are close enough for automatic translation
    static_assert(TargetSignatureT::arg_count == HostSignatureT::arg_count, "Syscall argument counts don't match!");

    // Translate arguments
    translate_arguments<TargetDetailsT, TargetSignatureT, HostSignatureT, TargetSignatureT::arg_count>(parameters);
}

template <typename TargetDetailsT>
auto syscall_rewriter_linux_ppc64le<TargetDetailsT>::invoke_syscall(int64_t target_number,
                                                                    const SyscallParameters &parameters)
                                                                    -> std::variant<status_code, SyscallRet> {
    int64_t generic_number = TargetDetailsT::get_generic_syscall_number(target_number);
    SyscallLinuxPPC64 native_number = generic_to_native_syscall(generic_number);
    SyscallParameters modified_parameters = parameters;
    switch (native_number) {
        // For auto syscalls, try to automatically match up syscall arguments.
        // Any type mismatch will result in a compile error.
#define declare_case(name, ...) \
        case SyscallLinuxPPC64::name: \
        { \
            validate_and_translate_arguments<TargetDetailsT, TargetDetailsT::SyscallNumberT::name, \
                                             SyscallLinuxPPC64::name>(modified_parameters); \
            goto auto_common; \
        }
        ENUMERATE_AUTO_SYSCALLS(declare_case)
#undef declare_case
        auto_common:
        {
            // After the arguments have been validated and translated if necessary,
            // invoke the syscall.
            long res = syscall(
                (long)native_number,
                modified_parameters.args[0],
                modified_parameters.args[1],
                modified_parameters.args[2],
                modified_parameters.args[3],
                modified_parameters.args[4],
                modified_parameters.args[5]
            );
            return SyscallRet { res, false };
        }

        //
        // Special cases
        //

        case SyscallLinuxPPC64::exit:
            return SyscallRet { modified_parameters.args[0], true };

        case SyscallLinuxPPC64::INVALID:
            return status_code::UNIMPL_SYSCALL;

        default:
            pr_error("Unimplemented ppc64le syscall: %s (%" PRId64 ")\n", syscall_name((int64_t)native_number),
                     (int64_t)native_number);
            return status_code::UNIMPL_SYSCALL;
    }
}

template <typename TargetDetailsT>
SyscallLinuxPPC64 syscall_rewriter_linux_ppc64le<TargetDetailsT>::generic_to_native_syscall(int64_t generic_number_) {
    SyscallLinuxGeneric generic_number = (SyscallLinuxGeneric)generic_number_;
    switch (generic_number) {
        // Map all generic syscalls that are also available on ppc64 directly
        case SyscallLinuxGeneric::write: return SyscallLinuxPPC64::write;
        case SyscallLinuxGeneric::open: return SyscallLinuxPPC64::open;
        case SyscallLinuxGeneric::close: return SyscallLinuxPPC64::close;
        case SyscallLinuxGeneric::stat: return SyscallLinuxPPC64::stat;
        case SyscallLinuxGeneric::fstat: return SyscallLinuxPPC64::fstat;
        case SyscallLinuxGeneric::lstat: return SyscallLinuxPPC64::lstat;
        case SyscallLinuxGeneric::poll: return SyscallLinuxPPC64::poll;
        case SyscallLinuxGeneric::lseek: return SyscallLinuxPPC64::lseek;
        case SyscallLinuxGeneric::mmap: return SyscallLinuxPPC64::mmap;
        case SyscallLinuxGeneric::mprotect: return SyscallLinuxPPC64::mprotect;
        case SyscallLinuxGeneric::munmap: return SyscallLinuxPPC64::munmap;
        case SyscallLinuxGeneric::brk: return SyscallLinuxPPC64::brk;
        case SyscallLinuxGeneric::rt_sigaction: return SyscallLinuxPPC64::rt_sigaction;
        case SyscallLinuxGeneric::rt_sigprocmask: return SyscallLinuxPPC64::rt_sigprocmask;
        case SyscallLinuxGeneric::rt_sigreturn: return SyscallLinuxPPC64::rt_sigreturn;
        case SyscallLinuxGeneric::ioctl: return SyscallLinuxPPC64::ioctl;
        case SyscallLinuxGeneric::pread64: return SyscallLinuxPPC64::pread64;
        case SyscallLinuxGeneric::pwrite64: return SyscallLinuxPPC64::pwrite64;
        case SyscallLinuxGeneric::readv: return SyscallLinuxPPC64::readv;
        case SyscallLinuxGeneric::writev: return SyscallLinuxPPC64::writev;
        case SyscallLinuxGeneric::access: return SyscallLinuxPPC64::access;
        case SyscallLinuxGeneric::pipe: return SyscallLinuxPPC64::pipe;
        case SyscallLinuxGeneric::select: return SyscallLinuxPPC64::select;
        case SyscallLinuxGeneric::sched_yield: return SyscallLinuxPPC64::sched_yield;
        case SyscallLinuxGeneric::mremap: return SyscallLinuxPPC64::mremap;
        case SyscallLinuxGeneric::msync: return SyscallLinuxPPC64::msync;
        case SyscallLinuxGeneric::mincore: return SyscallLinuxPPC64::mincore;
        case SyscallLinuxGeneric::madvise: return SyscallLinuxPPC64::madvise;
        case SyscallLinuxGeneric::shmget: return SyscallLinuxPPC64::shmget;
        case SyscallLinuxGeneric::shmat: return SyscallLinuxPPC64::shmat;
        case SyscallLinuxGeneric::shmctl: return SyscallLinuxPPC64::shmctl;
        case SyscallLinuxGeneric::dup: return SyscallLinuxPPC64::dup;
        case SyscallLinuxGeneric::dup2: return SyscallLinuxPPC64::dup2;
        case SyscallLinuxGeneric::pause: return SyscallLinuxPPC64::pause;
        case SyscallLinuxGeneric::nanosleep: return SyscallLinuxPPC64::nanosleep;
        case SyscallLinuxGeneric::getitimer: return SyscallLinuxPPC64::getitimer;
        case SyscallLinuxGeneric::alarm: return SyscallLinuxPPC64::alarm;
        case SyscallLinuxGeneric::setitimer: return SyscallLinuxPPC64::setitimer;
        case SyscallLinuxGeneric::getpid: return SyscallLinuxPPC64::getpid;
        case SyscallLinuxGeneric::sendfile: return SyscallLinuxPPC64::sendfile;
        case SyscallLinuxGeneric::socket: return SyscallLinuxPPC64::socket;
        case SyscallLinuxGeneric::connect: return SyscallLinuxPPC64::connect;
        case SyscallLinuxGeneric::accept: return SyscallLinuxPPC64::accept;
        case SyscallLinuxGeneric::sendto: return SyscallLinuxPPC64::sendto;
        case SyscallLinuxGeneric::recvfrom: return SyscallLinuxPPC64::recvfrom;
        case SyscallLinuxGeneric::sendmsg: return SyscallLinuxPPC64::sendmsg;
        case SyscallLinuxGeneric::recvmsg: return SyscallLinuxPPC64::recvmsg;
        case SyscallLinuxGeneric::shutdown: return SyscallLinuxPPC64::shutdown;
        case SyscallLinuxGeneric::bind: return SyscallLinuxPPC64::bind;
        case SyscallLinuxGeneric::listen: return SyscallLinuxPPC64::listen;
        case SyscallLinuxGeneric::getsockname: return SyscallLinuxPPC64::getsockname;
        case SyscallLinuxGeneric::getpeername: return SyscallLinuxPPC64::getpeername;
        case SyscallLinuxGeneric::socketpair: return SyscallLinuxPPC64::socketpair;
        case SyscallLinuxGeneric::setsockopt: return SyscallLinuxPPC64::setsockopt;
        case SyscallLinuxGeneric::getsockopt: return SyscallLinuxPPC64::getsockopt;
        case SyscallLinuxGeneric::clone: return SyscallLinuxPPC64::clone;
        case SyscallLinuxGeneric::fork: return SyscallLinuxPPC64::fork;
        case SyscallLinuxGeneric::vfork: return SyscallLinuxPPC64::vfork;
        case SyscallLinuxGeneric::execve: return SyscallLinuxPPC64::execve;
        case SyscallLinuxGeneric::exit: return SyscallLinuxPPC64::exit;
        case SyscallLinuxGeneric::wait4: return SyscallLinuxPPC64::wait4;
        case SyscallLinuxGeneric::kill: return SyscallLinuxPPC64::kill;
        case SyscallLinuxGeneric::uname: return SyscallLinuxPPC64::uname;
        case SyscallLinuxGeneric::semget: return SyscallLinuxPPC64::semget;
        case SyscallLinuxGeneric::semctl: return SyscallLinuxPPC64::semctl;
        case SyscallLinuxGeneric::shmdt: return SyscallLinuxPPC64::shmdt;
        case SyscallLinuxGeneric::msgget: return SyscallLinuxPPC64::msgget;
        case SyscallLinuxGeneric::msgsnd: return SyscallLinuxPPC64::msgsnd;
        case SyscallLinuxGeneric::msgrcv: return SyscallLinuxPPC64::msgrcv;
        case SyscallLinuxGeneric::msgctl: return SyscallLinuxPPC64::msgctl;
        case SyscallLinuxGeneric::fcntl: return SyscallLinuxPPC64::fcntl;
        case SyscallLinuxGeneric::flock: return SyscallLinuxPPC64::flock;
        case SyscallLinuxGeneric::fsync: return SyscallLinuxPPC64::fsync;
        case SyscallLinuxGeneric::fdatasync: return SyscallLinuxPPC64::fdatasync;
        case SyscallLinuxGeneric::truncate: return SyscallLinuxPPC64::truncate;
        case SyscallLinuxGeneric::ftruncate: return SyscallLinuxPPC64::ftruncate;
        case SyscallLinuxGeneric::getdents: return SyscallLinuxPPC64::getdents;
        case SyscallLinuxGeneric::getcwd: return SyscallLinuxPPC64::getcwd;
        case SyscallLinuxGeneric::chdir: return SyscallLinuxPPC64::chdir;
        case SyscallLinuxGeneric::fchdir: return SyscallLinuxPPC64::fchdir;
        case SyscallLinuxGeneric::rename: return SyscallLinuxPPC64::rename;
        case SyscallLinuxGeneric::mkdir: return SyscallLinuxPPC64::mkdir;
        case SyscallLinuxGeneric::rmdir: return SyscallLinuxPPC64::rmdir;
        case SyscallLinuxGeneric::creat: return SyscallLinuxPPC64::creat;
        case SyscallLinuxGeneric::link: return SyscallLinuxPPC64::link;
        case SyscallLinuxGeneric::unlink: return SyscallLinuxPPC64::unlink;
        case SyscallLinuxGeneric::symlink: return SyscallLinuxPPC64::symlink;
        case SyscallLinuxGeneric::readlink: return SyscallLinuxPPC64::readlink;
        case SyscallLinuxGeneric::chmod: return SyscallLinuxPPC64::chmod;
        case SyscallLinuxGeneric::fchmod: return SyscallLinuxPPC64::fchmod;
        case SyscallLinuxGeneric::chown: return SyscallLinuxPPC64::chown;
        case SyscallLinuxGeneric::fchown: return SyscallLinuxPPC64::fchown;
        case SyscallLinuxGeneric::lchown: return SyscallLinuxPPC64::lchown;
        case SyscallLinuxGeneric::umask: return SyscallLinuxPPC64::umask;
        case SyscallLinuxGeneric::gettimeofday: return SyscallLinuxPPC64::gettimeofday;
        case SyscallLinuxGeneric::getrlimit: return SyscallLinuxPPC64::getrlimit;
        case SyscallLinuxGeneric::getrusage: return SyscallLinuxPPC64::getrusage;
        case SyscallLinuxGeneric::sysinfo: return SyscallLinuxPPC64::sysinfo;
        case SyscallLinuxGeneric::times: return SyscallLinuxPPC64::times;
        case SyscallLinuxGeneric::ptrace: return SyscallLinuxPPC64::ptrace;
        case SyscallLinuxGeneric::getuid: return SyscallLinuxPPC64::getuid;
        case SyscallLinuxGeneric::syslog: return SyscallLinuxPPC64::syslog;
        case SyscallLinuxGeneric::getgid: return SyscallLinuxPPC64::getgid;
        case SyscallLinuxGeneric::setuid: return SyscallLinuxPPC64::setuid;
        case SyscallLinuxGeneric::setgid: return SyscallLinuxPPC64::setgid;
        case SyscallLinuxGeneric::geteuid: return SyscallLinuxPPC64::geteuid;
        case SyscallLinuxGeneric::getegid: return SyscallLinuxPPC64::getegid;
        case SyscallLinuxGeneric::setpgid: return SyscallLinuxPPC64::setpgid;
        case SyscallLinuxGeneric::getppid: return SyscallLinuxPPC64::getppid;
        case SyscallLinuxGeneric::getpgrp: return SyscallLinuxPPC64::getpgrp;
        case SyscallLinuxGeneric::setsid: return SyscallLinuxPPC64::setsid;
        case SyscallLinuxGeneric::setreuid: return SyscallLinuxPPC64::setreuid;
        case SyscallLinuxGeneric::setregid: return SyscallLinuxPPC64::setregid;
        case SyscallLinuxGeneric::getgroups: return SyscallLinuxPPC64::getgroups;
        case SyscallLinuxGeneric::setgroups: return SyscallLinuxPPC64::setgroups;
        case SyscallLinuxGeneric::setresuid: return SyscallLinuxPPC64::setresuid;
        case SyscallLinuxGeneric::getresuid: return SyscallLinuxPPC64::getresuid;
        case SyscallLinuxGeneric::setresgid: return SyscallLinuxPPC64::setresgid;
        case SyscallLinuxGeneric::getresgid: return SyscallLinuxPPC64::getresgid;
        case SyscallLinuxGeneric::getpgid: return SyscallLinuxPPC64::getpgid;
        case SyscallLinuxGeneric::setfsuid: return SyscallLinuxPPC64::setfsuid;
        case SyscallLinuxGeneric::setfsgid: return SyscallLinuxPPC64::setfsgid;
        case SyscallLinuxGeneric::getsid: return SyscallLinuxPPC64::getsid;
        case SyscallLinuxGeneric::capget: return SyscallLinuxPPC64::capget;
        case SyscallLinuxGeneric::capset: return SyscallLinuxPPC64::capset;
        case SyscallLinuxGeneric::rt_sigpending: return SyscallLinuxPPC64::rt_sigpending;
        case SyscallLinuxGeneric::rt_sigtimedwait: return SyscallLinuxPPC64::rt_sigtimedwait;
        case SyscallLinuxGeneric::rt_sigqueueinfo: return SyscallLinuxPPC64::rt_sigqueueinfo;
        case SyscallLinuxGeneric::rt_sigsuspend: return SyscallLinuxPPC64::rt_sigsuspend;
        case SyscallLinuxGeneric::sigaltstack: return SyscallLinuxPPC64::sigaltstack;
        case SyscallLinuxGeneric::utime: return SyscallLinuxPPC64::utime;
        case SyscallLinuxGeneric::mknod: return SyscallLinuxPPC64::mknod;
        case SyscallLinuxGeneric::uselib: return SyscallLinuxPPC64::uselib;
        case SyscallLinuxGeneric::personality: return SyscallLinuxPPC64::personality;
        case SyscallLinuxGeneric::ustat: return SyscallLinuxPPC64::ustat;
        case SyscallLinuxGeneric::statfs: return SyscallLinuxPPC64::statfs;
        case SyscallLinuxGeneric::fstatfs: return SyscallLinuxPPC64::fstatfs;
        case SyscallLinuxGeneric::sysfs: return SyscallLinuxPPC64::sysfs;
        case SyscallLinuxGeneric::getpriority: return SyscallLinuxPPC64::getpriority;
        case SyscallLinuxGeneric::setpriority: return SyscallLinuxPPC64::setpriority;
        case SyscallLinuxGeneric::sched_setparam: return SyscallLinuxPPC64::sched_setparam;
        case SyscallLinuxGeneric::sched_getparam: return SyscallLinuxPPC64::sched_getparam;
        case SyscallLinuxGeneric::sched_setscheduler: return SyscallLinuxPPC64::sched_setscheduler;
        case SyscallLinuxGeneric::sched_getscheduler: return SyscallLinuxPPC64::sched_getscheduler;
        case SyscallLinuxGeneric::sched_get_priority_max: return SyscallLinuxPPC64::sched_get_priority_max;
        case SyscallLinuxGeneric::sched_get_priority_min: return SyscallLinuxPPC64::sched_get_priority_min;
        case SyscallLinuxGeneric::sched_rr_get_interval: return SyscallLinuxPPC64::sched_rr_get_interval;
        case SyscallLinuxGeneric::mlock: return SyscallLinuxPPC64::mlock;
        case SyscallLinuxGeneric::munlock: return SyscallLinuxPPC64::munlock;
        case SyscallLinuxGeneric::mlockall: return SyscallLinuxPPC64::mlockall;
        case SyscallLinuxGeneric::munlockall: return SyscallLinuxPPC64::munlockall;
        case SyscallLinuxGeneric::vhangup: return SyscallLinuxPPC64::vhangup;
        case SyscallLinuxGeneric::modify_ldt: return SyscallLinuxPPC64::modify_ldt;
        case SyscallLinuxGeneric::pivot_root: return SyscallLinuxPPC64::pivot_root;
        case SyscallLinuxGeneric::_sysctl: return SyscallLinuxPPC64::_sysctl;
        case SyscallLinuxGeneric::prctl: return SyscallLinuxPPC64::prctl;
        case SyscallLinuxGeneric::adjtimex: return SyscallLinuxPPC64::adjtimex;
        case SyscallLinuxGeneric::setrlimit: return SyscallLinuxPPC64::setrlimit;
        case SyscallLinuxGeneric::chroot: return SyscallLinuxPPC64::chroot;
        case SyscallLinuxGeneric::sync: return SyscallLinuxPPC64::sync;
        case SyscallLinuxGeneric::acct: return SyscallLinuxPPC64::acct;
        case SyscallLinuxGeneric::settimeofday: return SyscallLinuxPPC64::settimeofday;
        case SyscallLinuxGeneric::mount: return SyscallLinuxPPC64::mount;
        case SyscallLinuxGeneric::umount2: return SyscallLinuxPPC64::umount2;
        case SyscallLinuxGeneric::swapon: return SyscallLinuxPPC64::swapon;
        case SyscallLinuxGeneric::swapoff: return SyscallLinuxPPC64::swapoff;
        case SyscallLinuxGeneric::reboot: return SyscallLinuxPPC64::reboot;
        case SyscallLinuxGeneric::sethostname: return SyscallLinuxPPC64::sethostname;
        case SyscallLinuxGeneric::setdomainname: return SyscallLinuxPPC64::setdomainname;
        case SyscallLinuxGeneric::iopl: return SyscallLinuxPPC64::iopl;
        case SyscallLinuxGeneric::ioperm: return SyscallLinuxPPC64::ioperm;
        case SyscallLinuxGeneric::create_module: return SyscallLinuxPPC64::create_module;
        case SyscallLinuxGeneric::init_module: return SyscallLinuxPPC64::init_module;
        case SyscallLinuxGeneric::delete_module: return SyscallLinuxPPC64::delete_module;
        case SyscallLinuxGeneric::get_kernel_syms: return SyscallLinuxPPC64::get_kernel_syms;
        case SyscallLinuxGeneric::query_module: return SyscallLinuxPPC64::query_module;
        case SyscallLinuxGeneric::quotactl: return SyscallLinuxPPC64::quotactl;
        case SyscallLinuxGeneric::nfsservctl: return SyscallLinuxPPC64::nfsservctl;
        case SyscallLinuxGeneric::getpmsg: return SyscallLinuxPPC64::getpmsg;
        case SyscallLinuxGeneric::putpmsg: return SyscallLinuxPPC64::putpmsg;
        case SyscallLinuxGeneric::afs_syscall: return SyscallLinuxPPC64::afs_syscall;
        case SyscallLinuxGeneric::tuxcall: return SyscallLinuxPPC64::tuxcall;
        case SyscallLinuxGeneric::gettid: return SyscallLinuxPPC64::gettid;
        case SyscallLinuxGeneric::readahead: return SyscallLinuxPPC64::readahead;
        case SyscallLinuxGeneric::setxattr: return SyscallLinuxPPC64::setxattr;
        case SyscallLinuxGeneric::lsetxattr: return SyscallLinuxPPC64::lsetxattr;
        case SyscallLinuxGeneric::fsetxattr: return SyscallLinuxPPC64::fsetxattr;
        case SyscallLinuxGeneric::getxattr: return SyscallLinuxPPC64::getxattr;
        case SyscallLinuxGeneric::lgetxattr: return SyscallLinuxPPC64::lgetxattr;
        case SyscallLinuxGeneric::fgetxattr: return SyscallLinuxPPC64::fgetxattr;
        case SyscallLinuxGeneric::listxattr: return SyscallLinuxPPC64::listxattr;
        case SyscallLinuxGeneric::llistxattr: return SyscallLinuxPPC64::llistxattr;
        case SyscallLinuxGeneric::flistxattr: return SyscallLinuxPPC64::flistxattr;
        case SyscallLinuxGeneric::removexattr: return SyscallLinuxPPC64::removexattr;
        case SyscallLinuxGeneric::lremovexattr: return SyscallLinuxPPC64::lremovexattr;
        case SyscallLinuxGeneric::fremovexattr: return SyscallLinuxPPC64::fremovexattr;
        case SyscallLinuxGeneric::tkill: return SyscallLinuxPPC64::tkill;
        case SyscallLinuxGeneric::time: return SyscallLinuxPPC64::time;
        case SyscallLinuxGeneric::futex: return SyscallLinuxPPC64::futex;
        case SyscallLinuxGeneric::sched_setaffinity: return SyscallLinuxPPC64::sched_setaffinity;
        case SyscallLinuxGeneric::sched_getaffinity: return SyscallLinuxPPC64::sched_getaffinity;
        case SyscallLinuxGeneric::io_setup: return SyscallLinuxPPC64::io_setup;
        case SyscallLinuxGeneric::io_destroy: return SyscallLinuxPPC64::io_destroy;
        case SyscallLinuxGeneric::io_getevents: return SyscallLinuxPPC64::io_getevents;
        case SyscallLinuxGeneric::io_submit: return SyscallLinuxPPC64::io_submit;
        case SyscallLinuxGeneric::io_cancel: return SyscallLinuxPPC64::io_cancel;
        case SyscallLinuxGeneric::lookup_dcookie: return SyscallLinuxPPC64::lookup_dcookie;
        case SyscallLinuxGeneric::epoll_create: return SyscallLinuxPPC64::epoll_create;
        case SyscallLinuxGeneric::remap_file_pages: return SyscallLinuxPPC64::remap_file_pages;
        case SyscallLinuxGeneric::getdents64: return SyscallLinuxPPC64::getdents64;
        case SyscallLinuxGeneric::set_tid_address: return SyscallLinuxPPC64::set_tid_address;
        case SyscallLinuxGeneric::restart_syscall: return SyscallLinuxPPC64::restart_syscall;
        case SyscallLinuxGeneric::semtimedop: return SyscallLinuxPPC64::semtimedop;
        case SyscallLinuxGeneric::fadvise64: return SyscallLinuxPPC64::fadvise64;
        case SyscallLinuxGeneric::timer_create: return SyscallLinuxPPC64::timer_create;
        case SyscallLinuxGeneric::timer_settime: return SyscallLinuxPPC64::timer_settime;
        case SyscallLinuxGeneric::timer_gettime: return SyscallLinuxPPC64::timer_gettime;
        case SyscallLinuxGeneric::timer_getoverrun: return SyscallLinuxPPC64::timer_getoverrun;
        case SyscallLinuxGeneric::timer_delete: return SyscallLinuxPPC64::timer_delete;
        case SyscallLinuxGeneric::clock_settime: return SyscallLinuxPPC64::clock_settime;
        case SyscallLinuxGeneric::clock_gettime: return SyscallLinuxPPC64::clock_gettime;
        case SyscallLinuxGeneric::clock_getres: return SyscallLinuxPPC64::clock_getres;
        case SyscallLinuxGeneric::clock_nanosleep: return SyscallLinuxPPC64::clock_nanosleep;
        case SyscallLinuxGeneric::exit_group: return SyscallLinuxPPC64::exit_group;
        case SyscallLinuxGeneric::epoll_wait: return SyscallLinuxPPC64::epoll_wait;
        case SyscallLinuxGeneric::epoll_ctl: return SyscallLinuxPPC64::epoll_ctl;
        case SyscallLinuxGeneric::tgkill: return SyscallLinuxPPC64::tgkill;
        case SyscallLinuxGeneric::utimes: return SyscallLinuxPPC64::utimes;
        case SyscallLinuxGeneric::mbind: return SyscallLinuxPPC64::mbind;
        case SyscallLinuxGeneric::set_mempolicy: return SyscallLinuxPPC64::set_mempolicy;
        case SyscallLinuxGeneric::get_mempolicy: return SyscallLinuxPPC64::get_mempolicy;
        case SyscallLinuxGeneric::mq_open: return SyscallLinuxPPC64::mq_open;
        case SyscallLinuxGeneric::mq_unlink: return SyscallLinuxPPC64::mq_unlink;
        case SyscallLinuxGeneric::mq_timedsend: return SyscallLinuxPPC64::mq_timedsend;
        case SyscallLinuxGeneric::mq_timedreceive: return SyscallLinuxPPC64::mq_timedreceive;
        case SyscallLinuxGeneric::mq_notify: return SyscallLinuxPPC64::mq_notify;
        case SyscallLinuxGeneric::mq_getsetattr: return SyscallLinuxPPC64::mq_getsetattr;
        case SyscallLinuxGeneric::kexec_load: return SyscallLinuxPPC64::kexec_load;
        case SyscallLinuxGeneric::waitid: return SyscallLinuxPPC64::waitid;
        case SyscallLinuxGeneric::add_key: return SyscallLinuxPPC64::add_key;
        case SyscallLinuxGeneric::request_key: return SyscallLinuxPPC64::request_key;
        case SyscallLinuxGeneric::keyctl: return SyscallLinuxPPC64::keyctl;
        case SyscallLinuxGeneric::ioprio_set: return SyscallLinuxPPC64::ioprio_set;
        case SyscallLinuxGeneric::ioprio_get: return SyscallLinuxPPC64::ioprio_get;
        case SyscallLinuxGeneric::inotify_init: return SyscallLinuxPPC64::inotify_init;
        case SyscallLinuxGeneric::inotify_add_watch: return SyscallLinuxPPC64::inotify_add_watch;
        case SyscallLinuxGeneric::inotify_rm_watch: return SyscallLinuxPPC64::inotify_rm_watch;
        case SyscallLinuxGeneric::migrate_pages: return SyscallLinuxPPC64::migrate_pages;
        case SyscallLinuxGeneric::openat: return SyscallLinuxPPC64::openat;
        case SyscallLinuxGeneric::mkdirat: return SyscallLinuxPPC64::mkdirat;
        case SyscallLinuxGeneric::mknodat: return SyscallLinuxPPC64::mknodat;
        case SyscallLinuxGeneric::fchownat: return SyscallLinuxPPC64::fchownat;
        case SyscallLinuxGeneric::futimesat: return SyscallLinuxPPC64::futimesat;
        case SyscallLinuxGeneric::newfstatat: return SyscallLinuxPPC64::newfstatat;
        case SyscallLinuxGeneric::unlinkat: return SyscallLinuxPPC64::unlinkat;
        case SyscallLinuxGeneric::renameat: return SyscallLinuxPPC64::renameat;
        case SyscallLinuxGeneric::linkat: return SyscallLinuxPPC64::linkat;
        case SyscallLinuxGeneric::symlinkat: return SyscallLinuxPPC64::symlinkat;
        case SyscallLinuxGeneric::readlinkat: return SyscallLinuxPPC64::readlinkat;
        case SyscallLinuxGeneric::fchmodat: return SyscallLinuxPPC64::fchmodat;
        case SyscallLinuxGeneric::faccessat: return SyscallLinuxPPC64::faccessat;
        case SyscallLinuxGeneric::pselect6: return SyscallLinuxPPC64::pselect6;
        case SyscallLinuxGeneric::ppoll: return SyscallLinuxPPC64::ppoll;
        case SyscallLinuxGeneric::unshare: return SyscallLinuxPPC64::unshare;
        case SyscallLinuxGeneric::set_robust_list: return SyscallLinuxPPC64::set_robust_list;
        case SyscallLinuxGeneric::get_robust_list: return SyscallLinuxPPC64::get_robust_list;
        case SyscallLinuxGeneric::splice: return SyscallLinuxPPC64::splice;
        case SyscallLinuxGeneric::tee: return SyscallLinuxPPC64::tee;
        case SyscallLinuxGeneric::vmsplice: return SyscallLinuxPPC64::vmsplice;
        case SyscallLinuxGeneric::move_pages: return SyscallLinuxPPC64::move_pages;
        case SyscallLinuxGeneric::utimensat: return SyscallLinuxPPC64::utimensat;
        case SyscallLinuxGeneric::epoll_pwait: return SyscallLinuxPPC64::epoll_pwait;
        case SyscallLinuxGeneric::signalfd: return SyscallLinuxPPC64::signalfd;
        case SyscallLinuxGeneric::timerfd_create: return SyscallLinuxPPC64::timerfd_create;
        case SyscallLinuxGeneric::eventfd: return SyscallLinuxPPC64::eventfd;
        case SyscallLinuxGeneric::fallocate: return SyscallLinuxPPC64::fallocate;
        case SyscallLinuxGeneric::timerfd_settime: return SyscallLinuxPPC64::timerfd_settime;
        case SyscallLinuxGeneric::timerfd_gettime: return SyscallLinuxPPC64::timerfd_gettime;
        case SyscallLinuxGeneric::accept4: return SyscallLinuxPPC64::accept4;
        case SyscallLinuxGeneric::signalfd4: return SyscallLinuxPPC64::signalfd4;
        case SyscallLinuxGeneric::eventfd2: return SyscallLinuxPPC64::eventfd2;
        case SyscallLinuxGeneric::epoll_create1: return SyscallLinuxPPC64::epoll_create1;
        case SyscallLinuxGeneric::dup3: return SyscallLinuxPPC64::dup3;
        case SyscallLinuxGeneric::pipe2: return SyscallLinuxPPC64::pipe2;
        case SyscallLinuxGeneric::inotify_init1: return SyscallLinuxPPC64::inotify_init1;
        case SyscallLinuxGeneric::preadv: return SyscallLinuxPPC64::preadv;
        case SyscallLinuxGeneric::pwritev: return SyscallLinuxPPC64::pwritev;
        case SyscallLinuxGeneric::rt_tgsigqueueinfo: return SyscallLinuxPPC64::rt_tgsigqueueinfo;
        case SyscallLinuxGeneric::perf_event_open: return SyscallLinuxPPC64::perf_event_open;
        case SyscallLinuxGeneric::recvmmsg: return SyscallLinuxPPC64::recvmmsg;
        case SyscallLinuxGeneric::fanotify_init: return SyscallLinuxPPC64::fanotify_init;
        case SyscallLinuxGeneric::fanotify_mark: return SyscallLinuxPPC64::fanotify_mark;
        case SyscallLinuxGeneric::prlimit64: return SyscallLinuxPPC64::prlimit64;
        case SyscallLinuxGeneric::name_to_handle_at: return SyscallLinuxPPC64::name_to_handle_at;
        case SyscallLinuxGeneric::open_by_handle_at: return SyscallLinuxPPC64::open_by_handle_at;
        case SyscallLinuxGeneric::clock_adjtime: return SyscallLinuxPPC64::clock_adjtime;
        case SyscallLinuxGeneric::syncfs: return SyscallLinuxPPC64::syncfs;
        case SyscallLinuxGeneric::sendmmsg: return SyscallLinuxPPC64::sendmmsg;
        case SyscallLinuxGeneric::setns: return SyscallLinuxPPC64::setns;
        case SyscallLinuxGeneric::getcpu: return SyscallLinuxPPC64::getcpu;
        case SyscallLinuxGeneric::process_vm_readv: return SyscallLinuxPPC64::process_vm_readv;
        case SyscallLinuxGeneric::process_vm_writev: return SyscallLinuxPPC64::process_vm_writev;
        case SyscallLinuxGeneric::kcmp: return SyscallLinuxPPC64::kcmp;
        case SyscallLinuxGeneric::finit_module: return SyscallLinuxPPC64::finit_module;
        case SyscallLinuxGeneric::sched_setattr: return SyscallLinuxPPC64::sched_setattr;
        case SyscallLinuxGeneric::sched_getattr: return SyscallLinuxPPC64::sched_getattr;
        case SyscallLinuxGeneric::renameat2: return SyscallLinuxPPC64::renameat2;
        case SyscallLinuxGeneric::seccomp: return SyscallLinuxPPC64::seccomp;
        case SyscallLinuxGeneric::getrandom: return SyscallLinuxPPC64::getrandom;
        case SyscallLinuxGeneric::memfd_create: return SyscallLinuxPPC64::memfd_create;
        case SyscallLinuxGeneric::kexec_file_load: return SyscallLinuxPPC64::kexec_file_load;
        case SyscallLinuxGeneric::bpf: return SyscallLinuxPPC64::bpf;
        case SyscallLinuxGeneric::execveat: return SyscallLinuxPPC64::execveat;
        case SyscallLinuxGeneric::userfaultfd: return SyscallLinuxPPC64::userfaultfd;
        case SyscallLinuxGeneric::membarrier: return SyscallLinuxPPC64::membarrier;
        case SyscallLinuxGeneric::mlock2: return SyscallLinuxPPC64::mlock2;
        case SyscallLinuxGeneric::copy_file_range: return SyscallLinuxPPC64::copy_file_range;
        case SyscallLinuxGeneric::preadv2: return SyscallLinuxPPC64::preadv2;
        case SyscallLinuxGeneric::pwritev2: return SyscallLinuxPPC64::pwritev2;
        case SyscallLinuxGeneric::pkey_mprotect: return SyscallLinuxPPC64::pkey_mprotect;
        case SyscallLinuxGeneric::pkey_alloc: return SyscallLinuxPPC64::pkey_alloc;
        case SyscallLinuxGeneric::pkey_free: return SyscallLinuxPPC64::pkey_free;
        case SyscallLinuxGeneric::statx: return SyscallLinuxPPC64::statx;

        default:
            pr_error("Unknown ppc64le equivalent for generic syscall: %s (%" PRId64 ")\n",
                     generic_linux_syscall_name(generic_number), generic_number_);
            return SyscallLinuxPPC64::INVALID;
    }
}

// Specializations for target=PPC64 (currently unsupported)
template <>
auto syscall_rewriter_linux_ppc64le<SyscallDetailsLinuxPPC64LE>::invoke_syscall(int64_t, const SyscallParameters &)
                                                                         -> std::variant<status_code, SyscallRet> {
    ASSERT_NOT_REACHED();
}

template <>
SyscallLinuxPPC64 syscall_rewriter_linux_ppc64le<SyscallDetailsLinuxPPC64LE>::generic_to_native_syscall(int64_t) {
    ASSERT_NOT_REACHED();
}

// Explicitly instantiate for all supported targets
#define instantiate(_, details) \
    template class retrec::syscall_rewriter_linux_ppc64le<details>;
ENUMERATE_ALL_LINUX_SYSCALL_DETAILS(instantiate)
#undef instantiate
