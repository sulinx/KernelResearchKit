# ARTIFACT compatibility layer

This fork of [KernelResearchKit](https://github.com/CodeStartUp/KernelResearchKit)
adds support for running alongside the **ARTIFACT** loader that Denuvo +
hypervisor-protected games ship with (Phantom Blade Zero, Crimson Desert, …).

Everything here was validated against real installations, not derived from
guesswork. Commands are additive — the upstream CLI is unchanged.

---

## 1. Why upstream behaviour breaks these games

Upstream's `load` command is `Stop → Patch DSE → Start driver → Restore DSE`.
That is correct when DrvLoader is the only party touching the driver.

ARTIFACT works differently. Its `artifact.dll` is injected into the **game
process**, and inside that process it does the equivalent of:

```
OpenSCManagerW  →  CreateServiceW("artifact", "\??\<game>\Artifact_Intel\hyperkd.sys")
                →  StartServiceW(...)
```

Two consequences:

1. **The SCM start happens later, and it re-checks signatures.** If DSE has
   already been restored, that `StartServiceW` fails with
   `0x80070241 ERROR_INVALID_IMAGE_HASH` (*"the hash for the file is not
   present in the specified catalog file"*), and the game dies on a modal
   titled **Artifact**. This is the single most common complaint.
2. **It installs a second instance of the same driver.** The service name
   (`artifact`) differs from the one DrvLoader creates (`hyperkd`), the image
   path differs (game folder vs `System32\drivers`), but it is the same bytes.
   `hyperkd.sys` has **no singleton guard** — no `IoCreateDevice`, no
   `STATUS_DEVICE_ALREADY_EXISTS` check — so `DriverEntry` runs twice and the
   second run re-initialises the global hypervisor state.

The observable failure for (2) is a **deterministic** crash:

```
Application Error 1000
  Faulting application: PBZ.exe
  Exception code: 0xc0000096        <- STATUS_PRIVILEGED_INSTRUCTION
  Fault offset:   0x00007ffde09dedc4   <- identical across runs
```

`0xC0000096` means the game executed a VMX instruction that only makes sense
inside the guest, but the VMM's bookkeeping had been clobbered.

---

## 2. The three new commands

### `drvloader compat [<dir|json>]`

Read-only. **Touches no kernel memory, needs no elevation, cannot crash
anything.** Use it to answer "can this machine run this game right now?".

```
[=== Compatibility check (read-only) ===]
[*] artifact.json    : OK  I:\...\platform\steam\artifact.json
    target           : PBZ.exe
    target exists    : YES  I:\...\platform\steam\PBZ.exe
[*] TESTSIGNING      : ON
[*] hyperkd.sys      : present  I:\...\Artifact_Intel\hyperkd.sys
[*] double-load      : none (safe)
[*] service hyperkd  : not installed
[*] service artifact : not installed
[*] service RTCore64 : \??\C:\Program Files (x86)\MSI Afterburner\RTCore64.sys

[=>] READY
```

Exit code `0` = ready, `1` = action needed.

Note that an unrelated `RTCore64` service owned by MSI Afterburner is reported
but **not** treated as a conflict — conflict detection compares resolved image
paths, not service names.

### `drvloader hold [--load <driver.sys>]`

Patches DSE and **keeps it patched**. Specifically:

* the destructor no longer auto-restores (upstream's `~DrvLoader` calls
  `RestoreDSE()` unconditionally, which is why `bypass` re-enabled DSE after
  ~160 ms);
* the console control handler no longer restores on Ctrl-C / window close;
* `RTCore64` stays loaded (upstream's `BypassDSE` already did this, but the
  destructor undid it on exit);
* the boot stamp is written so a later `restore` knows the state is live.

With `--load <driver.sys>` the target driver is also started, still without
restoring afterwards.

### `drvloader artifact <dir|json> [--launch] [--hold]`

The all-in-one entry point. It:

1. parses `artifact.json` (a small built-in JSON reader — no third-party
   dependency; handles `targets`, `load_dlls`, `arguments`, `autoload` and
   silently skips `hashes`/`tokens`/`patches`/`dlcs`);
2. derives the vendor branch from the CPU (`Artifact_Intel\hyperkd.sys` on
   Intel, `Artifact_AMD\SimpleSvm.sys` on AMD) and reports whether it exists;
3. reads `HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions` to report
   whether `TESTSIGNING` is on;
4. runs the double-load guard;
5. with `--hold`, engages the DSE hold;
6. with `--launch`, starts `targets[0]` with the configured `arguments` in the
   config's directory and **waits for it to exit**.

---

## 3. The two crash fixes

### 3.1 Double-load guard

`DrvLoader::LoadDriverResidentImpl()` enumerates
`HKLM\SYSTEM\CurrentControlSet\Services\*`, reads each `ImagePath`, expands
`\??\`, `\SystemRoot\`, `System32\` and environment variables, then compares
against the requested file by **volume serial + file index** (so 8.3 names,
junctions and different drive letters all match). Any hit other than the
service being created aborts the load:

```
[!] Refusing to load: this driver is already mapped by another service
    - artifact  (\??\I:\...\Artifact_Intel\hyperkd.sys)
[!] hyperkd.sys has no singleton guard - two instances will corrupt the
[!] hypervisor state and the game will die with 0xC0000096.
[*] Safe options:
    1) testsigning is ON -> just let ARTIFACT install the driver itself
    2) drvloader remove <name>  (for each service listed above), then retry
```

### 3.2 Stale patch state across reboots

`Initialize()` loads `OriginalCallback0..N` from
`HKCU\Software\drvloader\LatestState`. The registry survives a restart; the
kernel patch does not. Replaying a pre-reboot callback address writes a pointer
into `SeCiCallbacks` that belonged to a previous kernel layout — the classic
way to get `0x0000000A IRQL_NOT_LESS_OR_EQUAL` or a hard freeze from `restore`.

Fix: `ArtifactCompat::SavePatchBootStamp()` records a boot epoch
(`GetSystemTimeAsFileTime() - GetTickCount64()`, second resolution) whenever a
patch is applied. `IsPatchStateFromCurrentBoot()` compares it, and both
`Initialize()` and `RestoreDSEInternal()` refuse to replay state from a
different boot:

```
[!] Registry holds patch state from a PREVIOUS boot (8 callbacks)
[!] Discarding it: the kernel callbacks were reset by the restart,
[!] so replaying those addresses would corrupt SeCiCallbacks.
[+] Cleared patch state from registry (8 value(s) removed)
```

`ClearPatchStateFromRegistry()` was also incomplete upstream: it deleted the
singular `OriginalCallback` value but left `CallbackCount` + `OriginalCallback0..7`
behind, so the stale state came back on every start. It now sweeps the numbered
values too and reports how many it removed.

---

## 4. Recommended flow for a hypervisor game

**Option A — Test Signing (simplest, what the game's own `VBS.cmd` does)**

```powershell
bcdedit /set {current} testsigning on
# reboot
drvloader compat "<game dir>"     # expect [=>] READY
# then just launch the game; artifact.dll installs the driver itself
```

No DrvLoader involvement at all. Fine when the game ships no anti-cheat that
objects to the watermark.

**Option B — no watermark, DrvLoader holds DSE open**

```powershell
drvloader artifact "<game dir>" --launch --hold
# game runs; when you are done:
drvloader restore
```

`--hold` keeps the CI table patched for as long as the game lives, so
`artifact.dll`'s own `StartServiceW` succeeds, and the guard prevents the
double load from ever happening.

**Do not do this:** run `1-启动drvloader`-style `load` scripts *and* let
ARTIFACT install its own service. That is the exact configuration that
produces the `0xC0000096` crash.

---

## 5. Environment notes from validation

* Test box: Windows 11 build **26300.9711**, i9-13900K, VBS/HVCI/Secure Boot off.
  Kernel offsets used: `SeCiCallbacks = 0xf04e40`,
  `ZwFlushInstructionCache = 0x6aeef0`, callback slots at **`+0x8`** (not the
  `+0x20` the upstream README mentions), **8 contiguous slots** must be patched.
* `hyperkd.sys` and its companions are signed with a self-signed
  `CN="WDKTestCert artifact,…"` certificate that is in **no** trust store, so
  `Get-AuthenticodeSignature` reports `UnknownError`. That is why the plain SCM
  path needs `TESTSIGNING` (or the CI patch) to succeed.
* A `/analyze`-clean build produces `drvloader.exe` at **≈200 KB**; upstream's
  is ≈161 KB. Both are correct for their feature set.
* Building requires **MSVC v145** (Visual Studio 18 / 2026) and a **10.0**
  Windows SDK, matching `drvloader.vcxproj`:

  ```powershell
  & "<VS>\MSBuild\Current\Bin\MSBuild.exe" drvloader.vcxproj `
      /t:Rebuild /m:1 /nr:false /p:Configuration=Release /p:Platform=x64 `
      /p:BuildInParallel=false /p:MultiProcessorCompilation=false /p:CL_MPCount=1
  ```
