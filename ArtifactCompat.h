#pragma once

#include <Windows.h>
#include <string>
#include <vector>

// ============================================================================
// ArtifactCompat
// ----------------------------------------------------------------------------
// Helpers that let DrvLoader coexist with the ARTIFACT loader used by
// Denuvo+hypervisor games (Phantom Blade Zero / Crimson Desert & friends).
//
// The ARTIFACT runtime (artifact.dll) installs its OWN kernel service that
// points at the same hyperkd.sys we may have loaded.  Loading that driver
// twice corrupts the hypervisor's global state and the game dies with
// 0xC0000096 STATUS_PRIVILEGED_INSTRUCTION.  This module provides the
// detection / bookkeeping needed to avoid that, plus a tiny JSON reader for
// artifact.json (no third-party dependency).
// ============================================================================
namespace ArtifactCompat {

struct ArtifactConfig {
    std::wstring              configPath;
    std::vector<std::wstring> targets;      // e.g. "PBZ.exe"
    std::vector<std::wstring> loadDlls;     // e.g. "coldloader.dll"
    std::wstring              arguments;    // e.g. "ProjectPBZ -basedir ..."
    bool                      autoload{ true };
    bool                      valid{ false };
};

// Minimal artifact.json reader (handles the flat shape ARTIFACT ships:
// targets/load_dlls/arguments/autoload/hashes/tokens/patches).
bool LoadConfig(const std::wstring& path, ArtifactConfig& out);

// BCD SystemStartOptions, e.g. "TESTSIGNING NOEXECUTE=OPTIN ..."
std::wstring GetSystemStartOptions();

// True when the current boot has TESTSIGNING enabled (DSE is off for drivers).
bool IsTestSigningOn();

// Returns every kernel-driver service whose ImagePath resolves to the same
// file as `driverFile`, excluding `skipName`.  A non-empty result means
// loading that driver through drvloader would produce a SECOND instance.
std::vector<std::wstring> FindConflictingServices(const std::wstring& driverFile,
                                                  const std::wstring& skipName);

// Service name -> ImagePath (empty when the service does not exist)
std::wstring GetServiceImagePath(const std::wstring& serviceName);

// Boot-scoped bookkeeping.  A patch state recorded in an earlier boot is
// meaningless after a restart: the kernel callbacks are back to their original
// values, and replaying the stored addresses writes into freed/reused memory.
// That is exactly what produced the 0x0000000A style BSODs on this machine.
std::wstring CurrentBootStamp();
bool         SavePatchBootStamp();
bool         IsPatchStateFromCurrentBoot();
void         ClearPatchBootStamp();

// Launch the ARTIFACT target and block until it exits.
bool LaunchAndWait(const std::wstring& exePath,
                   const std::wstring& arguments,
                   const std::wstring& workDir,
                   DWORD*              outExitCode);

// Resolve a possibly relative path against a base directory.
std::wstring ResolvePath(const std::wstring& baseDir, const std::wstring& maybeRelative);

} // namespace ArtifactCompat
