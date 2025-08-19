// ControlledBSOD_UM.cpp  -- hardened diagnostic client
// Build as C++ (Visual Studio). Run elevated. Use in VMs only.

#include <windows.h>
#include <stdio.h>
#include <inttypes.h>
#include <string>
#include <sstream>
#include <map>
#include "bugcheck_table.h"
#define DEVICE_PATH L"\\\\.\\BSODLauncher"

// IOCTLs (must match driver definitions)
#define IOCTL_TRIGGER_BSOD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ARM          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Driver Definitions
#define DRIVER_NAME      L"ControlledBSOD"
#define DRIVER_DISPLAY   L"Controlled BSOD Driver"
#define DRIVER_FILENAME  L"ControlledBSOD.sys"

// structures from driver
typedef struct _BSOD_REQUEST {
    ULONG      BugCheckCode;
    ULONG_PTR  Param1;
    ULONG_PTR  Param2;
    ULONG_PTR  Param3;
    ULONG_PTR  Param4;
} BSOD_REQUEST;

typedef struct _ARM_REQUEST {
    ULONG64 Nonce;
} ARM_REQUEST;

typedef struct _STATUS_REPLY {
    ULONG   Version;
    BOOLEAN IsArmed;
    BOOLEAN IsVM;
    ULONG   LastClientPid;
    ULONG   Reserved;
} STATUS_REPLY;

// --- Bugcheck Symbol Table (expand as needed) ---

static const wchar_t* LookupBugCheckName(ULONG code) {
    auto it = BugCheckNames.find(code);
    return (it != BugCheckNames.end()) ? it->second : L"UNKNOWN";
}

// --- Utility Functions ---
static void PrintErrorMessage(DWORD err) {
    LPSTR msg = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;
    if (FormatMessageA(flags, NULL, err, 0, (LPSTR)&msg, 0, NULL) && msg) {
        fprintf(stderr, "Error %u: %s", err, msg);
        LocalFree(msg);
    }
    else {
        fprintf(stderr, "Error %u (no description)\n", err);
    }
}

static BOOL IsProcessElevated(void) {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te = { 0 };
        DWORD ret = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &ret)) {
            elevated = (te.TokenIsElevated != 0);
        }
        CloseHandle(token);
    }
    return elevated;
}

static BOOL SimpleIsVM(void) {
    // 1. Environment variable hints
    char buf[128];
    if (GetEnvironmentVariableA("VBOX_HWVIRTEX", buf, sizeof(buf))) return TRUE;
    if (GetEnvironmentVariableA("VMWARE_HWVIRTEX", buf, sizeof(buf))) return TRUE;

    // 2. Hypervisor bit in CPUID (leaf 1, ECX[31])
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor present. Identify vendor string.
        char hvVendor[13] = { 0 };
        __cpuid(cpuInfo, 0x40000000);
        memcpy(hvVendor + 0, &cpuInfo[1], 4); // EBX
        memcpy(hvVendor + 4, &cpuInfo[2], 4); // ECX
        memcpy(hvVendor + 8, &cpuInfo[3], 4); // EDX
        hvVendor[12] = '\0';

        if (strstr(hvVendor, "Microsoft") != nullptr) return TRUE; // Hyper-V
        if (strstr(hvVendor, "VMware") != nullptr) return TRUE;
        if (strstr(hvVendor, "VBox") != nullptr) return TRUE;
        if (strstr(hvVendor, "KVM") != nullptr) return TRUE;
        if (strstr(hvVendor, "Xen") != nullptr) return TRUE;
        return TRUE; // some hypervisor we don't recognize
    }

    // 3. BIOS/SMBIOS strings (quick registry sniff)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char sysVendor[256]; DWORD sz = sizeof(sysVendor);
        if (RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)sysVendor, &sz) == ERROR_SUCCESS) {
            if (strstr(sysVendor, "VBOX") || strstr(sysVendor, "VMWARE") || strstr(sysVendor, "XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }

    // Otherwise assume bare metal
    return FALSE;
}

static bool EnableTestSigningAndRestart() {
    wprintf(L"[!] Driver signature verification failed (Error 577).\n");
    wprintf(L"[?] Enable BCD TestSigning mode to allow unsigned drivers? (type YES to continue): ");
    wchar_t buf[16];
    if (!fgetws(buf, 16, stdin)) return false;
    if (_wcsicmp(buf, L"YES\n") != 0 && _wcsicmp(buf, L"YES\r\n") != 0) {
        wprintf(L"[-] User declined enabling TestSigning.\n");
        return false;
    }
    int rc = _wsystem(L"bcdedit /set testsigning on");
    if (rc != 0) {
        wprintf(L"[!] Failed to enable testsigning (bcdedit exit=%d)\n", rc);
        return false;
    }
    wprintf(L"[+] TestSigning enabled successfully.\n");
    wprintf(L"[?] Restart is required. Restart now? (YES/NO): ");
    if (!fgetws(buf, 16, stdin)) return false;
    if (_wcsicmp(buf, L"YES\n") == 0 || _wcsicmp(buf, L"YES\r\n") == 0) {
        _wsystem(L"shutdown /r /t 5");
    }
    else {
        wprintf(L"[*] Please restart manually for changes to take effect.\n");
    }
    return true;
}

bool InstallAndStartService(const wchar_t* driverPath) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        wprintf(L"[!] OpenSCManager failed. Error=%lu\n", GetLastError());
        return false;
    }
    SC_HANDLE hService = OpenServiceW(hSCM, DRIVER_NAME, SERVICE_ALL_ACCESS);
    if (!hService) {
        hService = CreateServiceW(
            hSCM, DRIVER_NAME, DRIVER_DISPLAY, SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            driverPath, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!hService) {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_IMAGE_HASH) {
                CloseServiceHandle(hSCM);
                return EnableTestSigningAndRestart();
            }
            if (err != ERROR_SERVICE_EXISTS) {
                wprintf(L"[!] CreateService failed. Error=%lu\n", err);
                CloseServiceHandle(hSCM);
                return false;
            }
            hService = OpenServiceW(hSCM, DRIVER_NAME, SERVICE_ALL_ACCESS);
            if (!hService) {
                wprintf(L"[!] OpenService (after exists) failed. Error=%lu\n", GetLastError());
                CloseServiceHandle(hSCM);
                return false;
            }
        }
        else {
            wprintf(L"[+] Service created successfully.\n");
        }
    }
    else {
        wprintf(L"[*] Service already exists.\n");
    }
    if (!StartServiceW(hService, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            wprintf(L"[*] Service already running.\n");
        }
        else {
            wprintf(L"[!] StartService failed. Error=%lu\n", err);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    else {
        wprintf(L"[+] Service started successfully.\n");
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

static void PrintUsage(const wchar_t* exeName, bool verbose = false) {
    wprintf(L"Usage:\n");
    wprintf(L"  %s [options] <bugcheck_hex> [p1 p2 p3 p4]\n", exeName);
    wprintf(L"  %s --make-service [options]\n", exeName);
    wprintf(L"  %s --help\n", exeName);
    if (verbose) {
        wprintf(L"\nOptions:\n");
        wprintf(L"  --make-service   Install and start the driver service (needs %s in same folder).\n", DRIVER_FILENAME);
        wprintf(L"  --verbose        Enable detailed logging.\n");
        wprintf(L"  --no-vm-check    Skip hypervisor/VM detection.\n");
        wprintf(L"  --help           Show this help.\n");
        wprintf(L"\nExample:\n");
        wprintf(L"  %s --make-service --verbose\n", exeName);
        wprintf(L"  %s 0x0000001E --verbose\n", exeName);
        wprintf(L"  %s --make-service 0x000000D1 --verbose\n", exeName);
    }
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"[ControlledBSOD Client]\n");
    bool verbose = false, skipVM = false, makeService = false;

    // Parse all arguments first
    std::vector<std::wstring> nonFlagArgs;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--verbose") == 0) {
            verbose = true;
        }
        else if (_wcsicmp(argv[i], L"--no-vm-check") == 0) {
            skipVM = true;
        }
        else if (_wcsicmp(argv[i], L"--make-service") == 0) {
            makeService = true;
        }
        else if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0) {
            PrintUsage(argv[0], true);
            return 0;
        }
        else {
            // Non-flag argument (bugcheck code or parameters)
            nonFlagArgs.push_back(argv[i]);
        }
    }

    if (nonFlagArgs.empty() && !makeService) {
        PrintUsage(argv[0], verbose);
        return 1;
    }

    // Handle service installation if requested
    if (makeService) {
        if (!IsProcessElevated()) {
            fwprintf(stderr, L"[!] Please run this program as Administrator.\n");
            return 1;
        }

        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring path(exePath);
        size_t pos = path.find_last_of(L"\\/");
        std::wstring driverPath = path.substr(0, pos + 1) + DRIVER_FILENAME;
        if (verbose) wprintf(L"[*] Installing driver service from: %s\n", driverPath.c_str());
        if (InstallAndStartService(driverPath.c_str())) {
            wprintf(L"[+] Driver service ready.\n");
        }
        else {
            wprintf(L"[!] Failed to set up driver service: " + GetLastError());
            return 1;
        }

        // If only making service (no bugcheck code), exit here
        if (nonFlagArgs.empty()) {
            return 0;
        }
    }

    // If we have a bugcheck code to process
    if (!nonFlagArgs.empty()) {
        if (!IsProcessElevated()) {
            fwprintf(stderr, L"[!] Please run this program as Administrator.\n");
            return 1;
        }

        // Parse bugcheck code and parameters
        BSOD_REQUEST req = { 0 };
        std::wstringstream ss(nonFlagArgs[0]);
        ss >> std::hex >> req.BugCheckCode;

        if (nonFlagArgs.size() > 1) req.Param1 = wcstoull(nonFlagArgs[1].c_str(), nullptr, 16);
        if (nonFlagArgs.size() > 2) req.Param2 = wcstoull(nonFlagArgs[2].c_str(), nullptr, 16);
        if (nonFlagArgs.size() > 3) req.Param3 = wcstoull(nonFlagArgs[3].c_str(), nullptr, 16);
        if (nonFlagArgs.size() > 4) req.Param4 = wcstoull(nonFlagArgs[4].c_str(), nullptr, 16);

        const wchar_t* bcName = LookupBugCheckName(req.BugCheckCode);
        if (verbose) wprintf(L"[=] Bugcheck request: 0x%08X (%s) Params=0x%p 0x%p 0x%p 0x%p\n",
            req.BugCheckCode, bcName, (PVOID)req.Param1, (PVOID)req.Param2, (PVOID)req.Param3, (PVOID)req.Param4);

        if (!skipVM && !SimpleIsVM()) {
            wprintf(L"[!] No hypervisor detected. Continue anyway? (YES to confirm): ");
            char buf[16];
            if (!fgets(buf, sizeof(buf), stdin)) return 1;
            if (strncmp(buf, "YES", 3) != 0) return 1;
        }

        HANDLE h = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            fwprintf(stderr, L"[-] Cannot open %s\n", DEVICE_PATH);
            PrintErrorMessage(GetLastError());
            return 1;
        }

        DWORD bytes = 0;
        if (!DeviceIoControl(h, IOCTL_PING, NULL, 0, NULL, 0, &bytes, NULL)) {
            fwprintf(stderr, L"[-] Driver PING failed.\n");
            CloseHandle(h);
            return 1;
        }
        if (verbose) wprintf(L"[+] Driver responded to PING.\n");

        ARM_REQUEST arm = { 0x12345678ABCDEFULL };
        if (!DeviceIoControl(h, IOCTL_ARM, &arm, sizeof(arm), NULL, 0, &bytes, NULL)) {
            fwprintf(stderr, L"[-] IOCTL_ARM failed.\n");
            CloseHandle(h);
            return 1;
        }
        if (verbose) wprintf(L"[+] IOCTL_ARM succeeded.\n");

        STATUS_REPLY st = { 0 };
        if (!DeviceIoControl(h, IOCTL_GET_STATUS, NULL, 0, &st, sizeof(st), &bytes, NULL)) {
            fwprintf(stderr, L"[-] IOCTL_GET_STATUS failed.\n");
            CloseHandle(h);
            return 1;
        }
        if (verbose) wprintf(L"[*] Driver status: Version=%u Armed=%u VM=%u\n", st.Version, st.IsArmed, st.IsVM);

        wprintf(L"[?] Final confirmation: trigger 0x%08X (%s)? Type YES to proceed: ", req.BugCheckCode, bcName);

        char confirm[16] = { 0 };
        if (!fgets(confirm, sizeof(confirm), stdin)) {
            CloseHandle(h);
            return 1;
        }
        if (strncmp(confirm, "YES", 3) != 0) {
            wprintf(L"[-] Aborted.\n");
            CloseHandle(h);
            return 1;
        }

        if (!DeviceIoControl(h, IOCTL_TRIGGER_BSOD, &req, sizeof(req), NULL, 0, &bytes, NULL)) {
            fwprintf(stderr, L"[-] IOCTL_TRIGGER_BSOD failed.\n");
            PrintErrorMessage(GetLastError());
            CloseHandle(h);
            return 1;
        }
        wprintf(L"[+] BugCheck request sent.\n");

        CloseHandle(h);
    }

    return 0;
}