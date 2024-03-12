#ifndef STRUCTS_H
#define STRUCTS_H
#define STATUS_SUCCESS              0x00000000
#define STATUS_BUFFER_TOO_SMALL     0xC0000023

#define THREAD_INTEGRITY_UNKNOWN   0
#define THREAD_INTEGRITY_LOW       1
#define THREAD_INTEGRITY_MEDIUM    2
#define THREAD_INTEGRITY_HIGH      3


typedef PUCHAR(NTAPI* fnRtlSubAuthorityCountSid)(IN PSID Sid);
typedef PULONG(NTAPI* fnRtlSubAuthoritySid)(IN PSID Sid, IN ULONG SubAuthority);

// Typedef for NtQueryInformationToken function pointer
typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength);

// Mapping function to convert integrity level DWORD to string
const char* IntegrityLevelToString(DWORD integrityLevel) {
    switch (integrityLevel) {
    case THREAD_INTEGRITY_LOW:
        return "Low Integrity";
    case THREAD_INTEGRITY_MEDIUM:
        return "Medium Integrity";
    case THREAD_INTEGRITY_HIGH:        
        return "High Integrity";
    case THREAD_INTEGRITY_UNKNOWN:
        return "Unknown Integrity Level";
    default:
        return "Unknown Integrity Level";
    }
}


#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_MOV_INSTRUCTION_OPCODE			0xB8		// 'mov'	- instruction opcode
#define	x64_SYSCALL_STUB_SIZE				0x20		// size of a syscall stub is 32


typedef enum PATCH
{
    PATCH_ETW_EVENTWRITE,
    PATCH_ETW_EVENTWRITE_FULL
};

#endif // STRUCTS_H
