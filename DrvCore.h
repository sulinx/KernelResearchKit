#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include "SymbolDownloader.h"

constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204C;

struct alignas(8) RTC_MEMORY_READ {
    BYTE Pad0[8];
    uint64_t Address;
    BYTE Pad1[8];
    uint32_t Size;
    uint32_t Value;
    BYTE Pad3[16];
};

struct alignas(8) RTC_MEMORY_WRITE {
    BYTE Pad0[8];
    uint64_t Address;
    BYTE Pad1[8];
    uint32_t Size;
    uint32_t Value;
    BYTE Pad3[16];
};

class DrvLoader {
public:
    HANDLE hDriver{ INVALID_HANDLE_VALUE };
    std::vector<uint64_t> originalCallbacks;
    std::optional<uint64_t> patchedCallbackAddr; // base of the patched block
    SymbolDownloader symbolDownloader;

    // ------------------------------------------------------------------
    // Resident ("hold") mode — added for ARTIFACT compatibility.
    //
    // In hold mode the destructor must NOT auto-restore DSE, and the helper
    // driver (RTCore64) is never unloaded while the patch is live.  ARTIFACT's
    // artifact.dll installs its own service on top of the same hyperkd.sys we
    // just loaded; tearing the patch down underneath it kills the game with
    // 0xC0000096.  `RestoreDSE()` remains available on demand.
    // ------------------------------------------------------------------
    bool                                         holdMode{ false };
    std::wstring                                 heldDriverPath; // driver we loaded, for conflict checks
    std::wstring                                 heldServiceName;

    // Cache for kernel offsets to avoid repeated PDB downloads/parsing
    std::optional<uint64_t> cachedSeCiOffset;
    std::optional<uint64_t> cachedZwFlushOffset;

    // Resolves necessary kernel symbol offsets
    bool GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction);
	
	// Strictly resolves kernel offsets from current ntoskrnl.exe PDB (no cache)
	std::optional<std::pair<uint64_t, uint64_t>> ResolveKernelOffsetsStrict();

	// Validates kernel addresses before patching
	bool ValidateKernelAddresses(uint64_t ntBase, uint64_t seCiRva, uint64_t zwRva);

	// Gets .text section bounds from ntoskrnl.exe on disk
	std::optional<std::pair<uint64_t, uint64_t>> GetTextSectionBounds(const std::wstring& ntoskrnlPath);
    
    // Initializes the loader and checks registry state
    bool Initialize();
    
    // Destructor to restore DSE automatically if patched
    ~DrvLoader();
    
    // Releases resources and handles
    void Cleanup();
    
    // Kernel memory operations
    bool WriteMemory32(uint64_t address, uint32_t value);
    bool WriteMemory64(uint64_t address, uint64_t value);
    std::optional<uint32_t> ReadMemory32(uint64_t address);
    std::optional<uint64_t> ReadMemory64(uint64_t address);
    
    // DSE Status and Manipulation
    bool CheckDSEStatus(bool& isPatched);
    // Pure-read DSE inspection: never installs/uninstalls drivers, never
    // patches.  Safe to call while a `hold` is live (status() is not).
    bool ReadDSEOnly(bool& isPatched);
    bool BypassDSE();
    bool RestoreDSE();

    // Resident hold: patch DSE and keep the helper driver loaded until
    // ExitHold()/RestoreDSE() is called explicitly.  Used by `drvloader hold`.
    bool EnterHold();
    // Restore DSE and unload RTCore64.  Safe to call when nothing is held.
    bool ExitHold();

    // Driver Management
    bool LoadDriver(const std::wstring& driverPath, DWORD startType = SERVICE_DEMAND_START, const std::wstring& dependencies = L"");
    // Same as LoadDriver but keeps the DSE patch alive afterwards (no restore).
    bool LoadDriverResident(const std::wstring& driverPath, DWORD startType = SERVICE_DEMAND_START, const std::wstring& dependencies = L"");
private:
    bool LoadDriverResidentImpl(const std::wstring& driverPath, DWORD startType,
                                const std::wstring& dependencies, bool resident);
public:
    bool ReloadDriver(const std::wstring& driverPath);
    bool StopDriver(const std::wstring& serviceNameOrPath);   // New: Stops service without deleting
    bool RemoveDriver(const std::wstring& serviceNameOrPath); // Renamed from UnloadDriver: Stops and deletes
    
private:
    std::optional<uint64_t> GetNtoskrnlBase();
    std::optional<uint64_t> GetKernelSymbolOffset(const std::wstring& symbolName);
    
    // Internal helpers for RTCore64 handling
    bool InstallAndStartDriver();
    bool StopAndRemoveDriver();
    bool CheckDriverFileExists();
    bool DriverServiceExists(const std::wstring& serviceName);
    
    // Internal DSE helpers
    bool BypassDSEInternal();
    bool RestoreDSEInternal();

    // Scan SeCiCallbacks structure to find the real CI callback slot
    // Returns the offset (relative to SeCiCallbacks base) of the first kernel-VA pointer
    std::optional<uint64_t> FindCallbackOffset(uint64_t seCiCallbacksVA, uint64_t ntBase);
};