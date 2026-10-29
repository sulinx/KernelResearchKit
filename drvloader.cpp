#include "UserInterface.h"
#include "DrvCore.h"
#include "ConfigManager.h"
#include "ArtifactCompat.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <windows.h>
#include <intrin.h>

static DrvLoader* g_Loader = nullptr;

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
        // In hold mode we deliberately do NOT restore: ARTIFACT may still be
        // running and pulling the patch out from under it kills the game with
        // 0xC0000096.  The operator restores explicitly with `drvloader restore`.
        if (g_Loader && g_Loader->holdMode) {
            std::wcout << L"\n[*] Hold mode: DSE stays patched after console exit\n";
            return FALSE;
        }
        if (g_Loader && !g_Loader->originalCallbacks.empty()) {
            std::wcout << L"\n[*] Intercepted console exit. Ensuring DSE is restored...\n";
            g_Loader->RestoreDSE();
        }
        return FALSE;
    }
    return FALSE;
}

// CLI Handlers
int HandleBypassCommand(DrvLoader& loader);
int HandleRestoreCommand(DrvLoader& loader);
int HandleStatusCommand(DrvLoader& loader);
int HandleLoadCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleReloadCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleRemoveCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleStopCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleHistoryCommand();
int HandleOffsetsCommand(DrvLoader& loader);
int HandleAutoLoadCommand(DrvLoader& loader);
int HandleHoldCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleArtifactCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleCompatCheckCommand(int argc, wchar_t* argv[]);
void ShowHelp();

int wmain(int argc, wchar_t* argv[]) {
    UI::DisplayBanner();

    // Safety check for HVCI
    if (!ConfigManager::CheckAndDisableMemoryIntegrity()) {
        return 1;
    }

    DrvLoader loader;
    g_Loader = &loader;
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    if (!loader.Initialize()) {
        std::wcout << L"\n[FAILED] Loader initialization failed\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

    // CLI Execution
    if (argc > 1) {
        std::wstring cmd = argv[1];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towlower);

        if (cmd == L"bypass") {
            return HandleBypassCommand(loader);
        }
        else if (cmd == L"restore") {
            return HandleRestoreCommand(loader);
        }
        else if (cmd == L"status") {
            return HandleStatusCommand(loader);
        }
        else if (cmd == L"load") {
            return HandleLoadCommand(loader, argc, argv);
        }
        else if (cmd == L"reload") {
            return HandleReloadCommand(loader, argc, argv);
        }
        else if (cmd == L"remove") {
            return HandleRemoveCommand(loader, argc, argv);
        }
        else if (cmd == L"stop") {
            return HandleStopCommand(loader, argc, argv);
        }
        else if (cmd == L"history") {
            return HandleHistoryCommand();
        }
        else if (cmd == L"offsets") {
            return HandleOffsetsCommand(loader);
        }
        else if (cmd == L"autoload") {
            return HandleAutoLoadCommand(loader);
        }
        else if (cmd == L"hold") {
            return HandleHoldCommand(loader, argc, argv);
        }
        else if (cmd == L"artifact") {
            return HandleArtifactCommand(loader, argc, argv);
        }
        else if (cmd == L"compat") {
            return HandleCompatCheckCommand(argc, argv);
        }
        else if (cmd == L"help" || cmd == L"/?" || cmd == L"-h" || cmd == L"--help") {
            ShowHelp();
            return 0;
        }
        else {
            std::wcout << L"[-] Unknown command: " << argv[1] << L"\n\n";
            ShowHelp();
            return 1;
        }
    }

    // Show interactive menu
    std::wcout << L"DSE Bypass Tool - Universal (Dynamic PDB)\n";
    std::wcout << L"==========================================\n";
    std::wcout << L"Technique: SeCiCallbacks replacement\n";
    std::wcout << L"Driver: RTCore64 (Embedded)\n";

    bool isPatched = false;
    if (!loader.CheckDSEStatus(isPatched)) {
        std::wcout << L"\n[FAILED] Could not check DSE status\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

    while (true) {
        UI::DisplayMenu(isPatched);

        int choice = 0;
        std::wcin >> choice;
        UI::ClearInputBuffer();

        if (choice == 1) {
            if (isPatched) {
                if (loader.RestoreDSE()) {
                    std::wcout << L"\n[SUCCESS] DSE Restored\n";
                    isPatched = false;
                }
                else {
                    std::wcout << L"\n[FAILED] Restore failed\n";
                }
            }
            else {
                if (loader.BypassDSE()) {
                    std::wcout << L"\n[SUCCESS] DSE Bypassed\n";
                    isPatched = true;
                }
                else {
                    std::wcout << L"\n[FAILED] Bypass failed\n";
                }
            }
            UI::WaitForAnyKey(L"\nPress any key...");
        }
        else if (choice == 2) {
            UI::DisplayLoadDriverMenu(loader);
        }
        else if (choice == 3) {
            UI::DisplayOffsetInfo(loader);
        }
        else if (choice == 4) {
            break;
        }
        else {
            std::wcout << L"\n[!] Invalid option\n";
        }
    }

    return 0;
}

int HandleBypassCommand(DrvLoader& loader) {
    return loader.BypassDSE() ? 0 : 1;
}

int HandleRestoreCommand(DrvLoader& loader) {
    return loader.RestoreDSE() ? 0 : 1;
}

int HandleStatusCommand(DrvLoader& loader) {
    bool isPatched = false;
    if (loader.CheckDSEStatus(isPatched)) return 0;
    return 1;
}

int HandleLoadCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    // If no driver path provided, open interactive menu
    if (argc == 2) {
        UI::DisplayLoadDriverMenu(loader, true);
        return 0;
    }

    std::wstring driverPath = argv[2];
    DWORD startType = SERVICE_DEMAND_START;

    // Check for optional start type flag (-s <type>)
    if (argc >= 5) {
        std::wstring flag = argv[3];
        std::transform(flag.begin(), flag.end(), flag.begin(), ::towlower);
        if (flag == L"-s") {
            startType = _wtoi(argv[4]);
        }
    }

    return loader.LoadDriver(driverPath, startType) ? 0 : 1;
}

int HandleReloadCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: drvloader reload <driver>\n";
        return 1;
    }
    return loader.ReloadDriver(argv[2]) ? 0 : 1;
}

int HandleRemoveCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: drvloader remove <driver>\n";
        return 1;
    }
    return loader.RemoveDriver(argv[2]) ? 0 : 1;
}

int HandleStopCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: drvloader stop <driver>\n";
        return 1;
    }
    return loader.StopDriver(argv[2]) ? 0 : 1;
}

int HandleHistoryCommand() {
    UI::DisplayDriverHistory();
    return 0;
}

int HandleOffsetsCommand(DrvLoader& loader) {
    UI::DisplayOffsetInfo(loader, false);
    return 0;
}

int HandleAutoLoadCommand(DrvLoader& loader) {
    return UI::AutoLoadDriver(loader, L"iamroot.sys") ? 0 : 1;
}

// ============================================================================
// ARTIFACT compatibility commands
// ============================================================================

// drvloader hold [--load <driver.sys>]
//   Patch DSE and keep it patched (RTCore64 stays loaded).  With --load the
//   target driver is also started, still without restoring afterwards.
int HandleHoldCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    std::wstring driverToLoad;
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);
        if (arg == L"--load" && i + 1 < argc) {
            driverToLoad = argv[++i];
        }
    }

    bool ok = false;
    if (driverToLoad.empty()) {
        ok = loader.EnterHold();
    } else {
        ok = loader.LoadDriverResident(driverToLoad, SERVICE_DEMAND_START);
    }

    if (!ok) {
        std::wcout << L"\n[FAILED] Hold not engaged\n";
        return 1;
    }

    std::wcout << L"\n[+] Hold engaged. DSE will stay patched until you run:\n";
    std::wcout << L"      drvloader restore\n";
    return 0;
}

// drvloader artifact <dir-or-json> [--launch] [--hold]
//   Read artifact.json, verify the environment, optionally patch DSE (hold),
//   optionally start the game, and wait for it to exit.
int HandleArtifactCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    std::wcout << L"\n[=== ARTIFACT compatibility mode ===]\n";

    std::wstring target;
    bool launch = false;
    bool hold   = false;

    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        std::wstring lower = arg;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower == L"--launch") { launch = true; continue; }
        if (lower == L"--hold")   { hold = true;   continue; }
        if (target.empty()) target = arg;
    }

    // Default to the directory this executable lives in.
    if (target.empty()) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring dir = exePath;
        size_t slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) dir = dir.substr(0, slash);
        target = dir;
    }

    // Accept either the JSON itself or the folder that contains it.
    std::wstring jsonPath = target;
    if (jsonPath.size() < 5 || _wcsicmp(jsonPath.c_str() + jsonPath.size() - 5, L".json") != 0) {
        if (!jsonPath.empty() && jsonPath.back() != L'\\' && jsonPath.back() != L'/')
            jsonPath += L'\\';
        jsonPath += L"artifact.json";
    }

    ArtifactCompat::ArtifactConfig cfg;
    if (!ArtifactCompat::LoadConfig(jsonPath, cfg)) {
        std::wcout << L"[-] Cannot read " << jsonPath << L"\n";
        std::wcout << L"[*] Pass either the artifact.json path or the folder containing it\n";
        return 1;
    }

    std::wstring baseDir = jsonPath;
    size_t slash = baseDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) baseDir = baseDir.substr(0, slash);

    std::wcout << L"[+] Config : " << jsonPath << L"\n";
    if (!cfg.targets.empty()) {
        std::wcout << L"[+] Targets: ";
        for (size_t i = 0; i < cfg.targets.size(); ++i) {
            if (i) std::wcout << L", ";
            std::wcout << cfg.targets[i];
        }
        std::wcout << L"\n";
    }
    if (!cfg.loadDlls.empty()) {
        std::wcout << L"[+] Load DLLs: ";
        for (size_t i = 0; i < cfg.loadDlls.size(); ++i) {
            if (i) std::wcout << L", ";
            std::wcout << cfg.loadDlls[i];
        }
        std::wcout << L"\n";
    }
    std::wcout << L"[+] Autoload: " << (cfg.autoload ? L"true" : L"false") << L"\n";

    // ---- Environment checks -------------------------------------------------
    std::wcout << L"\n[--- Environment ---]\n";
    bool testsigning = ArtifactCompat::IsTestSigningOn();
    std::wcout << L"[*] SystemStartOptions: "
               << (ArtifactCompat::GetSystemStartOptions().empty()
                       ? L"<unreadable>"
                       : ArtifactCompat::GetSystemStartOptions())
               << L"\n";
    std::wcout << L"[*] TESTSIGNING       : " << (testsigning ? L"ON" : L"OFF") << L"\n";

    // Which driver will ARTIFACT install?  It uses Artifact_Intel\hyperkd.sys or
    // Artifact_AMD\SimpleSvm.sys depending on the CPU.
    std::wstring vendorDir = L"Artifact_Intel";
    std::wstring driverName = L"hyperkd.sys";
#ifdef _M_ARM64
    vendorDir = L"Artifact_ARM64";
#else
    {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0);
        char vendor[13] = {};
        memcpy(vendor + 0, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[3], 4);
        memcpy(vendor + 8, &cpuInfo[2], 4);
        if (strcmp(vendor, "AuthenticAMD") == 0) {
            vendorDir  = L"Artifact_AMD";
            driverName = L"SimpleSvm.sys";
        }
    }
#endif

    std::wstring driverPath = ArtifactCompat::ResolvePath(baseDir, vendorDir + L"\\" + driverName);
    bool driverPresent = (GetFileAttributesW(driverPath.c_str()) != INVALID_FILE_ATTRIBUTES);
    std::wcout << L"[*] Vendor branch     : " << vendorDir << L"\n";
    std::wcout << L"[*] Driver            : " << driverPath
               << (driverPresent ? L"  (present)" : L"  (MISSING)") << L"\n";

    // ---- Double-load guard --------------------------------------------------
    auto conflicts = ArtifactCompat::FindConflictingServices(driverPath, L"");
    if (!conflicts.empty()) {
        std::wcout << L"\n[!] This driver is already mapped by:";
        for (const auto& c : conflicts) std::wcout << L" " << c;
        std::wcout << L"\n[!] ARTIFACT is about to install its own instance on top of it.\n";
        std::wcout << L"[!] Two hyperkd instances corrupt the hypervisor state (0xC0000096).\n";
    } else {
        std::wcout << L"[+] No other service maps this driver (no double-load risk)\n";
    }

    // ---- Optional hold ------------------------------------------------------
    if (hold) {
        std::wcout << L"\n[--- Holding DSE ---]\n";
        if (!loader.EnterHold()) {
            std::wcout << L"[-] Could not hold DSE\n";
            return 1;
        }
    } else if (!testsigning) {
        std::wcout << L"\n[!] TESTSIGNING is OFF.  If DSE is enforced, ARTIFACT's own service\n";
        std::wcout << L"[!] start will fail with 0x80070241 ERROR_INVALID_IMAGE_HASH.\n";
        std::wcout << L"[!] Either enable TESTSIGNING (VBS.cmd + reboot) or rerun with --hold.\n";
    }

    // ---- Launch -------------------------------------------------------------
    if (!launch) {
        std::wcout << L"\n[+] Environment reported. Nothing launched (pass --launch).\n";
        return 0;
    }

    if (cfg.targets.empty()) {
        std::wcout << L"[-] artifact.json has no 'targets' entry - cannot launch\n";
        return 1;
    }

    std::wstring exePath = ArtifactCompat::ResolvePath(baseDir, cfg.targets[0]);
    if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[-] Target not found: " << exePath << L"\n";
        return 1;
    }

    std::wcout << L"\n[--- Launch ---]\n";
    std::wcout << L"[*] " << exePath << L"\n";
    if (!cfg.arguments.empty())
        std::wcout << L"[*] args: " << cfg.arguments << L"\n";

    DWORD exitCode = 0;
    if (!ArtifactCompat::LaunchAndWait(exePath, cfg.arguments, baseDir, &exitCode)) {
        return 1;
    }
    std::wcout << L"[+] Process exited with code " << exitCode << L"\n";

    if (loader.holdMode) {
        std::wcout << L"[*] Hold mode: DSE is still patched. Run 'drvloader restore' when done.\n";
    }
    return 0;
}

// drvloader compat [<dir>]
//   Read-only diagnostic: no patching, no reboots. Reports whether the
//   environment is ready for ARTIFACT and whether a double load would occur.
int HandleCompatCheckCommand(int argc, wchar_t* argv[]) {
    std::wcout << L"\n[=== Compatibility check (read-only) ===]\n";

    std::wstring dir;
    if (argc >= 3) {
        dir = argv[2];
    } else {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring self = exePath;
        size_t slash = self.find_last_of(L"\\/");
        if (slash != std::wstring::npos) self = self.substr(0, slash);
        dir = self;
    }

    std::wstring jsonPath = dir;
    if (jsonPath.size() < 5 || _wcsicmp(jsonPath.c_str() + jsonPath.size() - 5, L".json") != 0) {
        if (!jsonPath.empty() && jsonPath.back() != L'\\' && jsonPath.back() != L'/')
            jsonPath += L'\\';
        jsonPath += L"artifact.json";
    }

    std::wstring baseDir = jsonPath;
    size_t slash = baseDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) baseDir = baseDir.substr(0, slash);

    ArtifactCompat::ArtifactConfig cfg;
    bool cfgOk = ArtifactCompat::LoadConfig(jsonPath, cfg);
    std::wcout << L"[*] artifact.json    : " << (cfgOk ? L"OK  " : L"MISSING  ") << jsonPath << L"\n";
    if (cfgOk && !cfg.targets.empty()) {
        std::wcout << L"    target           : " << cfg.targets[0] << L"\n";
        std::wstring exe = ArtifactCompat::ResolvePath(baseDir, cfg.targets[0]);
        std::wcout << L"    target exists    : "
                   << (GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES ? L"YES" : L"NO")
                   << L"  " << exe << L"\n";
    }

    bool ts = ArtifactCompat::IsTestSigningOn();
    std::wcout << L"[*] TESTSIGNING      : " << (ts ? L"ON" : L"OFF") << L"\n";

    std::wstring hyperkd = ArtifactCompat::ResolvePath(baseDir, L"Artifact_Intel\\hyperkd.sys");
    std::wcout << L"[*] hyperkd.sys      : "
               << (GetFileAttributesW(hyperkd.c_str()) != INVALID_FILE_ATTRIBUTES ? L"present" : L"missing")
               << L"  " << hyperkd << L"\n";

    auto conflicts = ArtifactCompat::FindConflictingServices(hyperkd, L"");
    if (conflicts.empty()) {
        std::wcout << L"[*] double-load      : none (safe)\n";
    } else {
        std::wcout << L"[*] double-load      : RISK - already mapped by";
        for (const auto& c : conflicts) std::wcout << L" " << c;
        std::wcout << L"\n";
    }

    // Anything already loaded from this vendor folder?
    for (const wchar_t* name : { L"hyperkd", L"artifact", L"RTCore64" }) {
        std::wstring img = ArtifactCompat::GetServiceImagePath(name);
        std::wcout << L"[*] service " << name << L" : "
                   << (img.empty() ? L"not installed" : img) << L"\n";
    }

    bool ok = cfgOk && (ts || conflicts.empty());
    std::wcout << L"\n[=>] " << (ok ? L"READY" : L"ACTION NEEDED") << L"\n";
    return ok ? 0 : 1;
}

void ShowHelp() {
    std::wcout << L"\nUsage: drvloader [command] [options]\n\n";
    std::wcout << L"Commands:\n";
    std::wcout << L"  (no args)              Auto-load iamroot.sys if present, else interactive mode\n";
    std::wcout << L"  bypass                 Disable DSE\n";
    std::wcout << L"  restore                Enable DSE\n";
    std::wcout << L"  status                 Check DSE status\n";
    std::wcout << L"  load <path>            Load driver (Stop -> Patch -> Start -> Restore)\n";
    std::wcout << L"  load <path> -s <0-4>   Load with specific StartType\n";
    std::wcout << L"  reload <driver>        Reload driver\n";
    std::wcout << L"  remove <driver>        Stop and delete service\n";
    std::wcout << L"  stop <driver>          Stop service (no delete)\n";
    std::wcout << L"  history                Show load history\n";
    std::wcout << L"  offsets                Dump offsets for external tools\n";
    std::wcout << L"  autoload               Auto-load iamroot.sys from same folder\n";
    std::wcout << L"\n";
    std::wcout << L"ARTIFACT compatibility (hypervisor games):\n";
    std::wcout << L"  hold [--load <path>]   Patch DSE and KEEP it patched (no auto-restore)\n";
    std::wcout << L"  artifact <dir|json>    Read artifact.json, check env, optional launch\n";
    std::wcout << L"                         flags: --launch  --hold\n";
    std::wcout << L"  compat [<dir|json>]    Read-only readiness check (no kernel access)\n";
    std::wcout << L"\n";
    std::wcout << L"StartType values:\n";
    std::wcout << L"  0 = SERVICE_BOOT_START\n";
    std::wcout << L"  1 = SERVICE_SYSTEM_START\n";
    std::wcout << L"  2 = SERVICE_AUTO_START\n";
    std::wcout << L"  3 = SERVICE_DEMAND_START (default)\n";
    std::wcout << L"  4 = SERVICE_DISABLED\n";
}