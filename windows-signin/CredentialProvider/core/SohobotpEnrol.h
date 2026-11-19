/*
 * SohobOTP (Sohobcom), 2026-11-12: set-up of a user's authenticator on the Windows sign-in
 * screen. The portal (portal/src/CpEnrol.php) checks the directory password, then answers with
 * a QR code (as a module matrix) and the key; the first code from the app finishes the set-up.
 * Requests and answers are sealed with the computer's own Sign-in secret (AES-256-GCM).
 * Licensed under the Apache License, Version 2.0, like the rest of this component.
 */
#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct SohobotpEnrolAnswer
{
	std::string status;   // scan, done, wrong_code, expired, not_needed, off
	std::wstring secret;  // key in groups of 4 (for typing it in the app)
	std::wstring message;
	std::vector<std::string> qr; // rows of '0'/'1', dark = '1'
};

namespace SohobotpEnrol
{
	// step: "start" (password) or "confirm" (code). false: no answer (portal unreachable,
	// not configured, or an answer that does not open with the secret).
	// localVerified: a local Windows account whose password this computer checked itself
	// (LogonUser); the password is then NOT sent, the portal relies on this computer's check.
	bool Request(const std::string& step, const std::wstring& user, const std::wstring& password,
		const std::wstring& code, SohobotpEnrolAnswer& answer, bool localVerified = false);

	// true: user is a local account of this computer (".", the computer name, or no domain on a
	// computer that is not in a domain) and password is its correct Windows password.
	bool CheckLocalPassword(const std::wstring& user, const std::wstring& domain, const std::wstring& password);

	// A local account of this computer: ".", the computer name, or a bare name on a computer
	// that is not in a domain.
	bool IsLocalAccount(const std::wstring& domain);

	// White background, black modules, quiet zone of 4 modules, about targetPixels wide.
	HBITMAP QrBitmap(const std::vector<std::string>& rows, int targetPixels);
}
