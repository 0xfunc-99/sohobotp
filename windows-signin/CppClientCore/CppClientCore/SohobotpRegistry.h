/*
 * SohobOTP (Sohobcom), 2026-11-12, SEC: the provider's settings and state are kept under
 * HKEY_CLASSES_ROOT\CLSID\{...}. HKEY_CLASSES_ROOT is a merged view: in a process running as the
 * user (credential prompts inside a session: UAC, Run as) it shows the user's own writable
 * HKCU\Software\Classes first, where a user could plant settings (server, without 2FA, excluded
 * account) or state. These wrappers send every HKEY_CLASSES_ROOT access to the machine-wide
 * HKLM\SOFTWARE\Classes, which only administrators and SYSTEM can write. Other roots unchanged.
 * Licensed under the Apache License, Version 2.0, like the rest of this component.
 */
#pragma once
#include <windows.h>
#include <string>

inline std::wstring SohobotpMachineClassesPath(LPCWSTR subKey)
{
	return std::wstring(L"SOFTWARE\\Classes\\") + (subKey != NULL ? subKey : L"");
}

inline LONG SohobotpRegOpenKeyEx(HKEY root, LPCWSTR subKey, DWORD options, REGSAM sam, PHKEY result)
{
	if (root == HKEY_CLASSES_ROOT) {
		return RegOpenKeyExW(HKEY_LOCAL_MACHINE, SohobotpMachineClassesPath(subKey).c_str(), options, sam, result);
	}
	return RegOpenKeyExW(root, subKey, options, sam, result);
}

inline LONG SohobotpRegCreateKeyEx(HKEY root, LPCWSTR subKey, DWORD reserved, LPWSTR keyClass, DWORD options, REGSAM sam,
	const LPSECURITY_ATTRIBUTES security, PHKEY result, LPDWORD disposition)
{
	if (root == HKEY_CLASSES_ROOT) {
		return RegCreateKeyExW(HKEY_LOCAL_MACHINE, SohobotpMachineClassesPath(subKey).c_str(), reserved, keyClass, options, sam, security, result, disposition);
	}
	return RegCreateKeyExW(root, subKey, reserved, keyClass, options, sam, security, result, disposition);
}

inline LONG SohobotpRegGetValue(HKEY root, LPCWSTR subKey, LPCWSTR value, DWORD flags, LPDWORD type, PVOID data, LPDWORD size)
{
	if (root == HKEY_CLASSES_ROOT) {
		return RegGetValueW(HKEY_LOCAL_MACHINE, SohobotpMachineClassesPath(subKey).c_str(), value, flags, type, data, size);
	}
	return RegGetValueW(root, subKey, value, flags, type, data, size);
}
