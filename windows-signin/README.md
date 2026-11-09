# SohobOTP Sign-in (Windows)

The Windows sign-in component of SohobOTP: it adds the SohobOTP code to Windows sign-in,
unlock, Remote Desktop and (optionally) administrator prompts. The SohobOTP agent configures
it from the portal (server URL, a secret for each computer, sign-in modes, offline cache).

Based on the multiOTP Credential Provider (Apache-2.0); see `NOTICE`, `LICENSE` and
`UPSTREAM-README.md` (the original documentation, including every registry setting).

| | |
|---|---|
| Provider CLSID | `{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}` |
| Filter CLSID | `{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A32}` |
| Settings | `HKEY_CLASSES_ROOT\CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}` (same value names as upstream, e.g. `multiOTPServers`) |
| Files | `SohobOTPSignIn.dll`, `SohobOTPSignInFilter.dll` (System32), `C:\Program Files\SohobOTP Sign-in\` |
| Installer | `SohobOTPSignIn.msi`, upgrade code `C8E1F0D4-2A9B-4E7C-B3F5-6A1D2E9C4B70` |

New CLSIDs mean it never clashes with an original multiOTP Credential Provider; uninstall that
one before installing SohobOTP Sign-in on a machine.

## Building (Windows only)

C++ with Visual Studio 2022 (v143, Windows SDK) and the WiX Toolset 3.14. It cannot be built on
Linux or macOS. Two ways:

- **GitHub Actions** (`.github/workflows/windows.yml`): builds the DLLs and the MSI on a
  Windows runner when this folder changes and keeps them as artefacts.
- **By hand** on Windows: run `get-php.ps1` once (embedded PHP runtime and SetACL, not stored in git), then
  `msbuild SohobOTPSignIn.sln /p:Configuration=Release /p:Platform=x64`; the MSI is in
  `WixInstall\multiOTPCredentialProviderInstaller\bin\x64\Release\`.

## Status

Renamed and rebranded only; the C++ logic is unchanged from upstream 5.10.4.1. Not yet built
or tested here (no Windows build machine). Planned in this fork: verify the portal's TLS
certificate in the bundled client, and encrypt the offline cache properly.
