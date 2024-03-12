#ifndef STRUCTS_H
#define STRUCTS_H

#include <Windows.h>
#include <winternl.h> // For NTSTATUS and TOKEN_INFORMATION_CLASS

// Typedef for NtQueryInformationToken function pointer
typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength);

#endif // STRUCTS_H
