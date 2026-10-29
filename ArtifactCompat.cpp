#include "ArtifactCompat.h"
#include <winternl.h>
#include <cstdio>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

namespace ArtifactCompat {

// ============================================================================
// Small helpers
// ============================================================================

static std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static std::wstring Trim(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n\"");
    if (b == std::wstring::npos) return L"";
    size_t e = s.find_last_not_of(L" \t\r\n\"");
    return s.substr(b, e - b + 1);
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

static bool ReadWholeFile(const std::wstring& path, std::string& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > (16 << 20)) {
        CloseHandle(h);
        return false;
    }

    out.resize((size_t)size.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)out.size(), &read, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    out.resize(read);

    // Strip UTF-8 BOM
    if (out.size() >= 3 && (BYTE)out[0] == 0xEF && (BYTE)out[1] == 0xBB && (BYTE)out[2] == 0xBF)
        out.erase(0, 3);
    return true;
}

// ============================================================================
// Minimal JSON reader
// ----------------------------------------------------------------------------
// Only what artifact.json needs: a flat object whose values are strings,
// booleans, numbers, arrays of strings, or nested objects/arrays (skipped).
// ============================================================================

namespace {

struct JsonReader {
    const char* p;
    const char* end;

    void SkipWs() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
    }

    bool Consume(char c) {
        SkipWs();
        if (p < end && *p == c) { ++p; return true; }
        return false;
    }

    // Parses a JSON string literal into `out`.  Handles \" \\ \/ \n \r \t \uXXXX.
    bool ParseString(std::string& out) {
        SkipWs();
        if (p >= end || *p != '"') return false;
        ++p;
        out.clear();
        while (p < end) {
            char c = *p++;
            if (c == '"') return true;
            if (c != '\\') { out.push_back(c); continue; }
            if (p >= end) return false;
            char e = *p++;
            switch (e) {
            case '"':  out.push_back('"');  break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/');  break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case 'u': {
                if (end - p < 4) return false;
                unsigned cp = 0;
                for (int i = 0; i < 4; ++i) {
                    char h = *p++;
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                    else return false;
                }
                // Encode as UTF-8 (BMP only; surrogates are rare in these configs)
                if (cp < 0x80) out.push_back((char)cp);
                else if (cp < 0x800) {
                    out.push_back((char)(0xC0 | (cp >> 6)));
                    out.push_back((char)(0x80 | (cp & 0x3F)));
                } else {
                    out.push_back((char)(0xE0 | (cp >> 12)));
                    out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back((char)(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default: break;
            }
        }
        return false;
    }

    // Skips an arbitrary JSON value (used for keys we do not care about).
    bool SkipValue() {
        SkipWs();
        if (p >= end) return false;
        if (*p == '"') { std::string tmp; return ParseString(tmp); }
        if (*p == '{' || *p == '[') {
            char open = *p;
            char close = (open == '{') ? '}' : ']';
            int depth = 0;
            while (p < end) {
                char c = *p++;
                if (c == '"') { --p; std::string tmp; if (!ParseString(tmp)) return false; continue; }
                if (c == open) ++depth;
                else if (c == close) {
                    if (--depth == 0) return true;
                }
            }
            return false;
        }
        // number / true / false / null
        while (p < end && *p != ',' && *p != '}' && *p != ']') ++p;
        return true;
    }

    bool ParseStringArray(std::vector<std::wstring>& out) {
        if (!Consume('[')) return false;
        SkipWs();
        if (Consume(']')) return true;
        while (p < end) {
            std::string s;
            if (!ParseString(s)) return false;
            out.push_back(Utf8ToWide(s));
            if (Consume(',')) continue;
            return Consume(']');
        }
        return false;
    }
};

} // namespace

bool LoadConfig(const std::wstring& path, ArtifactConfig& out) {
    out = ArtifactConfig{};
    out.configPath = path;

    std::string raw;
    if (!ReadWholeFile(path, raw)) return false;

    JsonReader r{ raw.data(), raw.data() + raw.size() };
    if (!r.Consume('{')) return false;

    bool first = true;
    while (r.p < r.end) {
        r.SkipWs();
        if (r.Consume('}')) break;
        if (!first) {
            if (!r.Consume(',')) break;
            r.SkipWs();
            if (r.Consume('}')) break;
        }
        first = false;

        std::string keyUtf8;
        if (!r.ParseString(keyUtf8)) break;
        if (!r.Consume(':')) break;

        std::wstring key = ToLower(Utf8ToWide(keyUtf8));

        if (key == L"targets") {
            r.ParseStringArray(out.targets);
        } else if (key == L"load_dlls" || key == L"loaddlls") {
            r.ParseStringArray(out.loadDlls);
        } else if (key == L"arguments") {
            std::string v;
            if (r.ParseString(v)) out.arguments = Utf8ToWide(v);
        } else if (key == L"autoload") {
            r.SkipWs();
            if (r.p < r.end) {
                if (*r.p == 't') { out.autoload = true;  r.SkipValue(); }
                else if (*r.p == 'f') { out.autoload = false; r.SkipValue(); }
                else { out.autoload = true; r.SkipValue(); }
            }
        } else {
            r.SkipValue();
        }
    }

    out.valid = true;
    return true;
}

// ============================================================================
// Boot / DSE state
// ============================================================================

std::wstring GetSystemStartOptions() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return L"";
    }

    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    std::wstring result;
    if (RegQueryValueExW(hKey, L"SystemStartOptions", nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
        result = buf;
    }
    RegCloseKey(hKey);
    return result;
}

bool IsTestSigningOn() {
    std::wstring opts = GetSystemStartOptions();
    // SystemStartOptions is space separated and upper-case; be forgiving.
    std::wstring upper = opts;
    for (auto& c : upper) c = (wchar_t)towupper(c);
    return upper.find(L"TESTSIGNING") != std::wstring::npos;
}

// ============================================================================
// Service <-> driver-file mapping
// ============================================================================

static std::wstring ExpandPath(const std::wstring& raw) {
    std::wstring s = Trim(raw);
    // Kernel image paths are commonly written as \??\C:\... — strip the prefix.
    if (s.rfind(L"\\??\\", 0) == 0) s = s.substr(4);
    if (s.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t sysRoot[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
        s = std::wstring(sysRoot) + s.substr(11);
    }
    if (s.find(L'%') != std::wstring::npos) {
        wchar_t expanded[MAX_PATH * 2] = {};
        if (ExpandEnvironmentStringsW(s.c_str(), expanded, MAX_PATH * 2))
            s = expanded;
    }
    // Relative "System32\drivers\x.sys" form
    if (s.size() > 2 && s[1] != L':') {
        wchar_t sysDir[MAX_PATH] = {};
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring lower = ToLower(s);
        if (lower.rfind(L"system32\\", 0) == 0) {
            s = std::wstring(sysDir) + s.substr(10);
        } else if (lower.rfind(L"\\system32\\", 0) == 0) {
            s = std::wstring(sysDir) + s.substr(11);
        } else {
            wchar_t winDir[MAX_PATH] = {};
            GetWindowsDirectoryW(winDir, MAX_PATH);
            s = std::wstring(winDir) + L"\\" + s;
        }
    }
    return s;
}

static bool SameFile(const std::wstring& a, const std::wstring& b) {
    if (ToLower(a) == ToLower(b)) return true;

    // Fall back to file identity so that different spellings (8.3 names,
    // junctions, different drive letters) still compare equal.
    HANDLE ha = CreateFileW(a.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (ha == INVALID_HANDLE_VALUE) return false;
    HANDLE hb = CreateFileW(b.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hb == INVALID_HANDLE_VALUE) { CloseHandle(ha); return false; }

    BY_HANDLE_FILE_INFORMATION ia{}, ib{};
    bool same = GetFileInformationByHandle(ha, &ia) && GetFileInformationByHandle(hb, &ib) &&
                ia.dwVolumeSerialNumber == ib.dwVolumeSerialNumber &&
                ia.nFileIndexHigh == ib.nFileIndexHigh &&
                ia.nFileIndexLow == ib.nFileIndexLow;
    CloseHandle(ha);
    CloseHandle(hb);
    return same;
}

std::wstring GetServiceImagePath(const std::wstring& serviceName) {
    std::wstring key = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";

    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    std::wstring result;
    if (RegQueryValueExW(hKey, L"ImagePath", nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
        result = buf;
    }
    RegCloseKey(hKey);
    return result;
}

std::vector<std::wstring> FindConflictingServices(const std::wstring& driverFile,
                                                  const std::wstring& skipName) {
    std::vector<std::wstring> conflicts;
    std::wstring wantLower = ToLower(skipName);

    HKEY hServices = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hServices) != ERROR_SUCCESS) {
        return conflicts;
    }

    wchar_t name[512];
    DWORD index = 0;
    while (RegEnumKeyW(hServices, index++, name, 512) == ERROR_SUCCESS) {
        if (ToLower(name) == wantLower) continue;

        std::wstring imagePath = GetServiceImagePath(name);
        if (imagePath.empty()) continue;

        std::wstring expanded = ExpandPath(imagePath);
        if (SameFile(expanded, driverFile)) {
            conflicts.push_back(name);
        }
    }

    RegCloseKey(hServices);
    return conflicts;
}

// ============================================================================
// Boot stamp
// ----------------------------------------------------------------------------
// Boot epoch = (current UTC FILETIME) - (GetTickCount64).  Stable to within a
// few ms inside one boot, completely different after a restart.  We compare at
// one-second resolution so scheduling jitter cannot produce false negatives.
// ============================================================================

std::wstring CurrentBootStamp() {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER nowVal;
    nowVal.LowPart  = now.dwLowDateTime;
    nowVal.HighPart = now.dwHighDateTime;

    ULONGLONG ticks100ns = GetTickCount64() * 10000ULL;
    ULONGLONG bootEpoch  = nowVal.QuadPart - ticks100ns;

    wchar_t buf[32];
    swprintf_s(buf, L"%llu", bootEpoch / 10000000ULL); // seconds
    return buf;
}

static const wchar_t* kStateKey = L"Software\\drvloader\\LatestState";
static const wchar_t* kBootValue = L"PatchBootStamp";

bool SavePatchBootStamp() {
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kStateKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                        &hKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    std::wstring stamp = CurrentBootStamp();
    LONG rc = RegSetValueExW(hKey, kBootValue, 0, REG_SZ,
                             reinterpret_cast<const BYTE*>(stamp.c_str()),
                             (DWORD)((stamp.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rc == ERROR_SUCCESS;
}

bool IsPatchStateFromCurrentBoot() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kStateKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    wchar_t buf[64] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(hKey, kBootValue, nullptr, &type,
                               reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) return false;

    return CurrentBootStamp() == std::wstring(buf);
}

void ClearPatchBootStamp() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kStateKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    RegDeleteValueW(hKey, kBootValue);
    RegCloseKey(hKey);
}

// ============================================================================
// Process launch
// ============================================================================

bool LaunchAndWait(const std::wstring& exePath,
                   const std::wstring& arguments,
                   const std::wstring& workDir,
                   DWORD*              outExitCode) {
    if (outExitCode) *outExitCode = (DWORD)-1;

    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!arguments.empty()) cmd += L" " + arguments;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring dir = workDir.empty() ? std::wstring() : workDir;
    BOOL ok = CreateProcessW(exePath.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                             0, nullptr,
                             dir.empty() ? nullptr : dir.c_str(),
                             &si, &pi);
    if (!ok) {
        std::wcout << L"[-] CreateProcess failed for " << exePath
                   << L" (error " << GetLastError() << L")\n";
        return false;
    }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);

    if (outExitCode) *outExitCode = code;
    return true;
}

std::wstring ResolvePath(const std::wstring& baseDir, const std::wstring& maybeRelative) {
    std::wstring s = Trim(maybeRelative);
    if (s.empty()) return s;
    if (s.size() > 2 && s[1] == L':') return s;
    if (s.rfind(L"\\\\", 0) == 0) return s;

    std::wstring joined = baseDir;
    if (!joined.empty() && joined.back() != L'\\' && joined.back() != L'/')
        joined += L'\\';
    joined += s;

    wchar_t full[MAX_PATH * 2] = {};
    if (GetFullPathNameW(joined.c_str(), MAX_PATH * 2, full, nullptr))
        return full;
    return joined;
}

} // namespace ArtifactCompat
