/*
 * This file defines the public interface between psxdll and libc (or any
 * statically linked ELF application)
 */

#pragma once

#include <nt.h>

/*
 * Information returned by stat, fstat, and lstat
 */
typedef struct _POSIX_STAT {
    /* TODO */
} POSIX_STAT, *PPOSIX_STAT;

/*
 * System call table for POSIX processes.
 */
typedef struct _POSIX_SYSCALL_TABLE {
    /* File I/O */
    SSIZE_T (*Read)(INT FileHandle, PVOID Buffer, SIZE_T Length);
    SSIZE_T (*Write)(INT FileHandle, PCVOID Buffer, SIZE_T Length);
    INT     (*Open)(PCSTR Pathname, INT Flags, UINT Mode);
    INT     (*Close)(INT FileHandle);
    INT64   (*Seek)(INT FileHandle, INT64 Offset, INT Whence);

    /* File metadata */
    INT     (*Stat)(PCSTR Pathname, PPOSIX_STAT StatBuffer);
    INT     (*FStat)(INT FileHandle, PPOSIX_STAT StatBuffer);
    INT     (*LStat)(PCSTR Pathname, PPOSIX_STAT StatBuffer);
    INT     (*Access)(PCSTR Pathname, INT Mode);
    INT     (*Unlink)(PCSTR Pathname);
    INT     (*Rename)(PCSTR OldPath, PCSTR NewPath);
    UINT    (*SetFileMask)(UINT NewMask);

    /* Directory Control */
    INT     (*MakeDir)(PCSTR Pathname, UINT Mode);
    INT     (*RemoveDir)(PCSTR Pathname);
    INT     (*GetDirectoryEntries)(INT DirFd, PVOID DirEntryBuffer, UINT BufferLength);
    INT     (*ChangeDirectory)(PCSTR Path);
    PCHAR   (*GetCurrentDirectory)(PCHAR Buffer, SIZE_T Size);
    SSIZE_T (*ReadLink)(PCSTR Pathname, PCHAR Buffer, SIZE_T Size);

    /* File Descriptors */
    INT     (*DuplicateHandle)(INT OldFd);
    INT     (*DuplicateHandleTo)(INT OldFd, INT NewFd);

    /* Pipes & Events */
    INT     (*CreatePipe)(INT PipeHandles[2]);
    INT     (*PollHandles)(PVOID Fds, UINT Count, INT Timeout);
    INT     (*SelectHandles)(INT Nfds, PVOID ReadFds, PVOID WriteFds,
			     PVOID ExceptFds, PVOID Timeout);

    /* Device Io Control */
    INT     (*IoControl)(INT FileHandle, INT Command, ...);

    /* Memory Management */
    PVOID   (*MapView)(PVOID BaseAddress, SIZE_T Length, INT Protection,
		       INT Flags, INT FileHandle, INT64 Offset);
    INT     (*UnmapView)(PVOID BaseAddress, SIZE_T Length);
    PVOID   (*RemapView)(PVOID OldAddress, SIZE_T OldSize, SIZE_T NewSize, INT Flags);
    INT     (*ProtectView)(PVOID Address, SIZE_T Length, INT Protection);
    PVOID   (*SetHeapBreak)(PVOID EndAddress);

    /* Process Control */
    INT     (*Fork)(VOID);
    INT     (*Execute)(PCSTR Filename, PCSTR *Arguments, PCSTR *Environment);
    INT     (*WaitForProcess)(INT Pid, PLONG ExitCode, INT Options, PVOID Usage);
    VOID    (*ExitProcess)(INT ExitCode);
    VOID    (*ExitThread)(INT ExitCode);

    /* Signal Handling */
    INT     (*SetSignalHandler)(INT Signal, PVOID Action, PVOID OldAction);
    INT     (*SetSignalMask)(INT How, PCVOID Set, PVOID OldSet);

    /* Timing */
    INT     (*Sleep)(PCVOID RequestedTime, PVOID RemainingTime);
    INT     (*GetClockTime)(INT ClockId, PVOID TimeSpec);
    INT     (*GetSystemTime)(PVOID TimeVal, PVOID TimeZone);

    /* Identity */
    UINT    (*GetUserId)(VOID);
    UINT    (*GetEffectiveUserId)(VOID);
    UINT    (*GetGroupId)(VOID);
    UINT    (*GetEffectiveGroupId)(VOID);
    INT     (*GetProcessId)(VOID);
    INT     (*GetParentProcessId)(VOID);

    /* System Info */
    INT     (*GetSystemInfo)(PVOID UtsName);
} POSIX_SYSCALL_TABLE, *PPOSIX_SYSCALL_TABLE;

/*
 * Process Environment Block of POSIX processes, which contains the system call table.
 */
typedef struct _PEB {
    POSIX_SYSCALL_TABLE SyscallTable;
    PVOID ImageBaseAddress;
} PEB, *PPEB;

/*
 * Thread Environment Block of POSIX processes
 */
typedef struct _TEB {
    NT_TIB NtTib;
    PPEB Peb;
} TEB, *PTEB;

FORCEINLINE NTAPI PTEB NtCurrentTeb(VOID)
{
    return (PVOID)NtCurrentTib();
}

FORCEINLINE NTAPI PPEB NtCurrentPeb(VOID)
{
    return NtCurrentTeb()->Peb;
}
