/*
 * SohobOTP (Sohobcom), 2026-11-12: set-up of a user's authenticator on the Windows sign-in
 * screen; see SohobotpEnrol.h and portal/src/CpEnrol.php (the wire format is defined there).
 * Licensed under the Apache License, Version 2.0, like the rest of this component.
 */
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include "SohobotpEnrol.h"
#include <bcrypt.h>
#include <lm.h> // NetGetJoinInformation (is this computer in a domain)
#include <winhttp.h>
#include <wincrypt.h>
#include <ctime>
#include "MultiOTPRegistryReader.h"
#include "MultiotpRegistry.h"
#include "Configuration.h"
#include "json.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

namespace
{
	std::string ToUtf8(const std::wstring& text)
	{
		if (text.empty()) {
			return std::string();
		}
		const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0, nullptr, nullptr);
		std::string out(size > 0 ? size : 0, '\0');
		if (size > 0) {
			WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], size, nullptr, nullptr);
		}
		return out;
	}

	std::wstring FromUtf8(const std::string& text)
	{
		if (text.empty()) {
			return std::wstring();
		}
		const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0);
		std::wstring out(size > 0 ? size : 0, L'\0');
		if (size > 0) {
			MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], size);
		}
		return out;
	}

	bool Random(BYTE* buffer, ULONG size)
	{
		return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
	}

	std::string Hex(const BYTE* data, size_t size)
	{
		static const char digits[] = "0123456789abcdef";
		std::string out;
		for (size_t i = 0; i < size; i++) {
			out += digits[data[i] >> 4];
			out += digits[data[i] & 15];
		}
		return out;
	}

	bool Sha256(const std::string& data, BYTE digest[32])
	{
		BCRYPT_ALG_HANDLE alg = nullptr;
		BCRYPT_HASH_HANDLE hash = nullptr;
		bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
			&& BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))
			&& BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR)data.data(), (ULONG)data.size(), 0))
			&& BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, 32, 0));
		if (hash) BCryptDestroyHash(hash);
		if (alg) BCryptCloseAlgorithmProvider(alg, 0);
		return ok;
	}

	// AES-256-GCM. encrypt: in = plaintext, out = ciphertext, tag written; decrypt: tag checked.
	bool AesGcm(bool encrypt, const BYTE key[32], const BYTE iv[12], const std::string& aad,
		const std::string& in, std::string& out, BYTE tag[16])
	{
		BCRYPT_ALG_HANDLE alg = nullptr;
		BCRYPT_KEY_HANDLE handle = nullptr;
		bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0))
			&& BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))
			&& BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &handle, nullptr, 0, (PUCHAR)key, 32, 0));
		if (ok) {
			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = (PUCHAR)iv;
			info.cbNonce = 12;
			info.pbAuthData = (PUCHAR)aad.data();
			info.cbAuthData = (ULONG)aad.size();
			info.pbTag = tag;
			info.cbTag = 16;
			out.assign(in.size(), '\0');
			ULONG written = 0;
			NTSTATUS status = encrypt
				? BCryptEncrypt(handle, (PUCHAR)in.data(), (ULONG)in.size(), &info, nullptr, 0, (PUCHAR)(out.empty() ? nullptr : &out[0]), (ULONG)out.size(), &written, 0)
				: BCryptDecrypt(handle, (PUCHAR)in.data(), (ULONG)in.size(), &info, nullptr, 0, (PUCHAR)(out.empty() ? nullptr : &out[0]), (ULONG)out.size(), &written, 0);
			ok = BCRYPT_SUCCESS(status) && written == in.size();
		}
		if (handle) BCryptDestroyKey(handle);
		if (alg) BCryptCloseAlgorithmProvider(alg, 0);
		return ok;
	}

	std::string Base64(const std::string& data)
	{
		DWORD size = 0;
		if (!CryptBinaryToStringA((const BYTE*)data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size)) {
			return std::string();
		}
		std::string out(size, '\0');
		if (!CryptBinaryToStringA((const BYTE*)data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &size)) {
			return std::string();
		}
		out.resize(size);
		return out;
	}

	bool Unbase64(const std::string& text, std::string& out)
	{
		DWORD size = 0;
		if (!CryptStringToBinaryA(text.c_str(), (DWORD)text.size(), CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr)) {
			return false;
		}
		out.assign(size, '\0');
		return CryptStringToBinaryA(text.c_str(), (DWORD)text.size(), CRYPT_STRING_BASE64, (BYTE*)&out[0], &size, nullptr, nullptr) != FALSE
			&& (out.resize(size), true);
	}

	// HTTPS POST. The certificate is not what protects the exchange (the messages are sealed
	// with the computer's secret), so a portal with its own certificate authority works too.
	bool Post(const std::wstring& url, const std::string& body, std::string& response, DWORD& statusCode)
	{
		URL_COMPONENTS parts = { 0 };
		wchar_t host[256] = { 0 };
		wchar_t path[2048] = { 0 };
		parts.dwStructSize = sizeof(parts);
		parts.lpszHostName = host;
		parts.dwHostNameLength = ARRAYSIZE(host);
		parts.lpszUrlPath = path;
		parts.dwUrlPathLength = ARRAYSIZE(path);
		parts.dwExtraInfoLength = (DWORD)-1;
		if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS) {
			return false;
		}
		std::wstring object(path);
		if (parts.lpszExtraInfo && parts.dwExtraInfoLength > 0) {
			object += std::wstring(parts.lpszExtraInfo, parts.dwExtraInfoLength);
		}
		bool ok = false;
		HINTERNET session = WinHttpOpen(L"SohobOTP Sign-in", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
		HINTERNET connection = session ? WinHttpConnect(session, host, parts.nPort, 0) : nullptr;
		HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST", object.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
		if (request) {
			WinHttpSetTimeouts(request, 5000, 5000, 15000, 15000);
			DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
			WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
			static const wchar_t headers[] = L"Content-Type: text/plain\r\n";
			if (WinHttpSendRequest(request, headers, (DWORD)-1L, (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0)
				&& WinHttpReceiveResponse(request, nullptr)) {
				DWORD size = sizeof(statusCode);
				WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
				response.clear();
				DWORD available = 0;
				ok = true;
				while (WinHttpQueryDataAvailable(request, &available) && available > 0 && response.size() < 65536) {
					std::string chunk(available, '\0');
					DWORD read = 0;
					if (!WinHttpReadData(request, &chunk[0], available, &read)) {
						ok = false;
						break;
					}
					response.append(chunk.data(), read);
				}
			}
		}
		if (request) WinHttpCloseHandle(request);
		if (connection) WinHttpCloseHandle(connection);
		if (session) WinHttpCloseHandle(session);
		return ok;
	}

	std::wstring RegistryString(const std::wstring& name)
	{
		MultiOTPRegistryReader reader(Configuration::registryPath);
		return reader.getRegistry(name);
	}

	std::wstring SharedSecret()
	{
		PWSTR value = nullptr;
		std::wstring secret;
		if (readRegistryValueString(CONF_SHARED_SECRET, &value, L"") > 1 && value != nullptr) {
			secret = value;
		}
		if (value) CoTaskMemFree(value);
		return secret;
	}
}

namespace SohobotpEnrol
{
	bool CheckLocalPassword(const std::wstring& user, const std::wstring& domain, const std::wstring& password)
	{
		if (user.empty() || password.empty()) {
			return false;
		}
		WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
		DWORD size = ARRAYSIZE(computer);
		GetComputerNameW(computer, &size);
		bool local = domain == L"." || (!domain.empty() && _wcsicmp(domain.c_str(), computer) == 0);
		if (domain.empty()) {
			// a bare name is a local account only on a computer that is not in a domain
			LPWSTR joined = nullptr;
			NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
			if (NetGetJoinInformation(nullptr, &joined, &status) == NERR_Success) {
				local = status != NetSetupDomainName;
				NetApiBufferFree(joined);
			}
		}
		if (!local) {
			return false;
		}
		HANDLE token = nullptr;
		// network logon: checks the password without needing the right to sign in at the console
		if (!LogonUserW(user.c_str(), L".", password.c_str(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token)) {
			return false;
		}
		CloseHandle(token);
		return true;
	}

	bool Request(const std::string& step, const std::wstring& user, const std::wstring& password,
		const std::wstring& code, SohobotpEnrolAnswer& answer, bool localVerified)
	{
		// the portal's address for this computer: https://host/portal/cp.php?e=<endpoint id>
		std::wstring url = RegistryString(L"multiOTPServers");
		const size_t separator = url.find_first_of(L";, ");
		if (separator != std::wstring::npos) {
			url = url.substr(0, separator);
		}
		const size_t idAt = url.find(L"cp.php?e=");
		const std::wstring secret = SharedSecret();
		if (idAt == std::wstring::npos || secret.empty()) {
			return false;
		}
		const std::string endpoint = ToUtf8(url.substr(idAt + 9, 20));
		BYTE key[32];
		BYTE nonceBytes[16];
		BYTE iv[12];
		BYTE tag[16];
		if (!Sha256("sohobotp-cp-enrol-v1" + ToUtf8(secret), key) || !Random(nonceBytes, 16) || !Random(iv, 12)) {
			return false;
		}
		const std::string nonce = Hex(nonceBytes, 16);
		nlohmann::json request = {
			{ "v", 1 }, { "t", (long long)time(nullptr) }, { "n", nonce }, { "step", step },
			{ "user", ToUtf8(user) }, { "password", localVerified ? std::string() : ToUtf8(password) }, { "code", ToUtf8(code) },
			{ "local", localVerified }
		};
		std::string plain = request.dump();
		std::string sealed;
		const bool encrypted = AesGcm(true, key, iv, endpoint, plain, sealed, tag);
		SecureZeroMemory(&plain[0], plain.size());
		if (!encrypted) {
			return false;
		}
		std::string response;
		DWORD status = 0;
		if (!Post(url + L"&a=enrol", Base64(std::string((const char*)iv, 12) + sealed + std::string((const char*)tag, 16)), response, status) || status != 200) {
			return false;
		}
		while (!response.empty() && (response.back() == '\n' || response.back() == '\r' || response.back() == ' ')) {
			response.pop_back();
		}
		std::string raw;
		if (!Unbase64(response, raw) || raw.size() < 29) {
			return false;
		}
		std::string opened;
		BYTE answerTag[16];
		memcpy(answerTag, raw.data() + raw.size() - 16, 16);
		if (!AesGcm(false, key, (const BYTE*)raw.data(), endpoint + "|" + nonce, raw.substr(12, raw.size() - 28), opened, answerTag)) {
			return false;
		}
		try {
			nlohmann::json reply = nlohmann::json::parse(opened);
			if (reply.value("n", std::string()) != nonce) {
				return false;
			}
			answer.status = reply.value("status", std::string());
			answer.secret = FromUtf8(reply.value("secret", std::string()));
			answer.message = FromUtf8(reply.value("message", std::string()));
			answer.qr.clear();
			if (reply.contains("qr") && reply["qr"].is_array()) {
				for (const auto& row : reply["qr"]) {
					if (row.is_string()) {
						answer.qr.push_back(row.get<std::string>());
					}
				}
			}
		}
		catch (...) {
			return false;
		}
		return !answer.status.empty();
	}

	HBITMAP QrBitmap(const std::vector<std::string>& rows, int targetPixels)
	{
		const int modules = (int)rows.size();
		if (modules < 21 || modules > 177) {
			return nullptr;
		}
		const int total = modules + 8; // quiet zone: 4 modules on each side
		int scale = targetPixels / total;
		if (scale < 2) {
			scale = 2;
		}
		const int size = total * scale;
		BITMAPINFO bmi = { 0 };
		bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bmi.bmiHeader.biWidth = size;
		bmi.bmiHeader.biHeight = -size; // top-down
		bmi.bmiHeader.biPlanes = 1;
		bmi.bmiHeader.biBitCount = 32;
		bmi.bmiHeader.biCompression = BI_RGB;
		void* bits = nullptr;
		HBITMAP bitmap = CreateDIBSection(nullptr, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
		if (bitmap == nullptr || bits == nullptr) {
			return nullptr;
		}
		DWORD* pixels = (DWORD*)bits;
		for (int y = 0; y < size; y++) {
			for (int x = 0; x < size; x++) {
				const int r = y / scale - 4;
				const int c = x / scale - 4;
				const bool dark = r >= 0 && c >= 0 && r < modules && c < modules && c < (int)rows[r].size() && rows[r][c] == '1';
				pixels[y * size + x] = dark ? 0xFF000000 : 0xFFFFFFFF;
			}
		}
		return bitmap;
	}
}
