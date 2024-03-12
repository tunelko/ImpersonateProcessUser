# ImpersonateProcess 

## Overview
The ImpersonateProcess project is a Windows-based utility written in C that demonstrates known techniques for security context manipulation, specifically focusing on impersonating the user associated with a given process ID (PID). This technique is essential for scenarios that require executing actions or commands with different user privileges, particularly for tasks that involve privilege escalation or system monitoring.

## Features
- **Enable Debug Privileges**: Automatically attempts to grant the calling process the necessary `SeDebugPrivilege`, which is crucial for accessing and manipulating other processes on the system.
- **Process Token Impersonation**: Provides functionality to duplicate a target process's access token and impersonate it, allowing the calling process to adopt the security context of the target process.
- **Execute Commands as Impersonated User**: Launches a new process (e.g., `cmd.exe`) using the impersonated user's security context, showcasing how to perform operations as another user.
- **Elevation Status Check**: Includes a utility function to check whether a given token is elevated, helping to determine if the impersonated context has administrative privileges.

## How It Works
The project consists of several key functions, each performing a specific role in the process of impersonation:
1. **`SetDebugPrivilege`**: Enables `SeDebugPrivilege` for the calling process, allowing it to access other processes more freely.
2. **`IsDebugPrivilegeEnabled`**: Verifies that the `SeDebugPrivilege` has been successfully enabled.
3. **`ImpersonateProcess`**: Given a PID, it opens the specified process, duplicates its token, and impersonates it.
4. **`LaunchCommandWithImpersonatedUser`**: Executes a specified command using the security context of the impersonated user.
5. **`IsTokenElevated`**: Checks if the impersonated token represents an elevated session.

## Usage
To use this utility, compile the provided C code snippets into an executable. Run the executable with administrative privileges to ensure it has the necessary permissions to enable `SeDebugPrivilege` and manipulate process tokens.

Example command line usage:
```
ImpersonateProcess.exe <PID>
```
Where `<PID>` is the process ID of the target process you wish to impersonate.

## Requirements
- Windows operating system
- Administrative privileges for the calling process
- C compiler (e.g., MSVC, MinGW ...) for building the executable
- Visual Studio Community Edition 2022 C/C++ 


## Disclaimer
This project is intended for educational purposes and should be used responsibly and ethically. This code is a part of training process of maldev-academy. Ensure you have authorization before impersonating processes, especially in environments that are not owned or managed by you.


