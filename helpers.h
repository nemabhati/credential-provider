#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "common.h"

// String conversion utilities
std::wstring AnsiToUnicode(const std::string& str);
std::string UnicodeToAnsi(const std::wstring& str);
std::string UnicodeToUtf8(const std::wstring& str);
std::wstring Utf8ToUnicode(const std::string& str);

// Memory management utilities
HRESULT SecureAllocateMemory(SIZE_T size, PVOID* ppBuffer);
HRESULT SecureFreeMemory(PVOID buffer, SIZE_T size);
HRESULT SecureStringCopy(PWSTR pszDest, SIZE_T cchDest, PCWSTR pszSrc);

// High-resolution timing utilities
HRESULT InitializePerformanceTimer();
HRESULT GetCurrentTimeStamp(LARGE_INTEGER* pTimeStamp);
DWORD CalculateElapsedTime(const LARGE_INTEGER& start, const LARGE_INTEGER& end);

// Keystroke analysis utilities
HRESULT CaptureKeystrokeEvent(WCHAR key, LONGLONG timestamp, DWORD position, KeystrokeData& keystroke);
HRESULT AnalyzeKeystrokePattern(const std::vector<KeystrokeData>& keystrokes, BiometricProfile& profile);
HRESULT ValidateKeystrokeData(const KeystrokeData& keystroke);

// JSON utilities
HRESULT CreateJSONString(const BiometricProfile& profile, std::wstring& jsonOutput);
HRESULT ParseJSONResponse(const std::wstring& jsonInput, AIResponse& response);
HRESULT EscapeJSONString(const std::wstring& input, std::wstring& output);

// HTTP/HTTPS utilities
HRESULT InitializeWinHTTP();
HRESULT CleanupWinHTTP();
HRESULT SendHTTPRequest(const std::wstring& endpoint, const std::wstring& data, const std::wstring& apiKey, std::wstring& response);
HRESULT ConfigureHTTPS(HINTERNET hRequest);

// Error handling utilities
HRESULT LogError(const std::wstring& message, HRESULT hr);
HRESULT GetLastErrorAsHRESULT();
void OutputDebugInfo(const std::wstring& message);

// Registry utilities
HRESULT ReadRegistryString(HKEY hKey, PCWSTR pszValueName, std::wstring& value);
HRESULT WriteRegistryString(HKEY hKey, PCWSTR pszValueName, const std::wstring& value);

// Cryptographic utilities
HRESULT GenerateRandomBytes(PBYTE buffer, DWORD size);
HRESULT HashData(PBYTE data, DWORD dataSize, PBYTE hash, DWORD hashSize);

// Validation utilities
BOOL IsValidPasswordLength(DWORD length);
BOOL IsValidKeystrokeTiming(LONGLONG downTime, LONGLONG upTime);
BOOL IsValidEndpoint(const std::wstring& endpoint);

// Resource management
class CAutoLock
{
public:
    CAutoLock(CRITICAL_SECTION* pcs) : m_pcs(pcs) { EnterCriticalSection(m_pcs); }
    ~CAutoLock() { LeaveCriticalSection(m_pcs); }
private:
    CRITICAL_SECTION* m_pcs;
};

// RAII wrapper for COM objects
template<class T>
class CComPtr
{
public:
    CComPtr() : m_ptr(nullptr) {}
    ~CComPtr() { if (m_ptr) m_ptr->Release(); }
    T** operator&() { return &m_ptr; }
    T* operator->() { return m_ptr; }
    T* Get() { return m_ptr; }
    void Release() { if (m_ptr) { m_ptr->Release(); m_ptr = nullptr; } }
private:
    T* m_ptr;
};

// RAII wrapper for handles
class CAutoHandle
{
public:
    CAutoHandle(HANDLE h = INVALID_HANDLE_VALUE) : m_handle(h) {}
    ~CAutoHandle() { if (m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }
    operator HANDLE() { return m_handle; }
    HANDLE* operator&() { return &m_handle; }
private:
    HANDLE m_handle;
};

// Constants
const DWORD MAX_PASSWORD_LENGTH = 256;
const DWORD MAX_ENDPOINT_LENGTH = 1024;
const DWORD MAX_API_KEY_LENGTH = 512;
const DWORD MAX_JSON_SIZE = 4096;
const DWORD MIN_KEYSTROKE_COUNT = 3;
const DWORD MAX_KEYSTROKE_COUNT = 256;