#pragma once

#include "common.h"
#include <string>
#include <vector>

// String conversion utilities
std::wstring AnsiToUnicode(const std::string& str);
std::string UnicodeToAnsi(const std::wstring& str);
std::string UnicodeToUtf8(const std::wstring& str);
std::wstring Utf8ToUnicode(const std::string& str);

// Configuration management
HRESULT GetConfigurationValue(PCWSTR pszValueName, std::wstring& value);
HRESULT SetConfigurationValue(PCWSTR pszValueName, PCWSTR pszValue);
HRESULT GetConfigurationDWORD(PCWSTR pszValueName, DWORD& value);
HRESULT SetConfigurationDWORD(PCWSTR pszValueName, DWORD value);

// Authentication package utilities
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);
HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, PWSTR* ppwzProtectedPassword);
HRESULT SplitDomainAndUsername(PCWSTR pszQualifiedUserName, PWSTR* ppszDomain, PWSTR* ppszUsername);

// Kerberos authentication utilities
HRESULT KerbInteractiveUnlockLogonInit(PCWSTR pwzDomain, PCWSTR pwzUsername, PCWSTR pwzPassword, 
                                      CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, KERB_INTERACTIVE_UNLOCK_LOGON* pkiul);
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& kiul, BYTE** ppbPackage, DWORD* pcbPackage);

// JSON utilities for AI communication
HRESULT CreateJSONString(const BiometricProfile& profile, std::wstring& jsonOutput);
HRESULT ParseJSONResponse(const std::wstring& jsonResponse, AIResponse& response);

// HTTP communication with AI model
HRESULT SendHTTPRequest(const std::wstring& endpoint, const std::wstring& jsonData, 
                       const std::wstring& apiKey, std::wstring& response);

// Security utilities
HRESULT SecureStringAllocate(PCWSTR pszSource, PWSTR* ppszDest);
HRESULT SecureStringDuplicate(PCWSTR pszSource, PWSTR* ppszDest);
void SecureStringFree(PWSTR pszString);
void SecureBufferCleanup(void* pBuffer, size_t size);

// Error handling utilities
HRESULT GetLastErrorAsHRESULT();
HRESULT GetNTStatusAsHRESULT(NTSTATUS status);
void LogError(PCWSTR pszMessage, HRESULT hr);
void LogInfo(PCWSTR pszMessage);

// Registry utilities
HRESULT OpenRegistryKey(HKEY hKeyParent, PCWSTR pszSubKey, DWORD dwDesiredAccess, HKEY* phKey);
HRESULT ReadRegistryString(HKEY hKey, PCWSTR pszValueName, std::wstring& value);
HRESULT WriteRegistryString(HKEY hKey, PCWSTR pszValueName, PCWSTR pszValue);
HRESULT ReadRegistryDWORD(HKEY hKey, PCWSTR pszValueName, DWORD& value);
HRESULT WriteRegistryDWORD(HKEY hKey, PCWSTR pszValueName, DWORD value);

// Timing utilities
LONGLONG GetHighPrecisionTime();
DWORD CalculateTimeDifference(LONGLONG startTime, LONGLONG endTime, LONGLONG frequency);

// Memory utilities
template<typename T>
void SafeDelete(T*& ptr)
{
    if (ptr)
    {
        delete ptr;
        ptr = nullptr;
    }
}

template<typename T>
void SafeDeleteArray(T*& ptr)
{
    if (ptr)
    {
        delete[] ptr;
        ptr = nullptr;
    }
}

// COM utilities
template<typename T>
void SafeRelease(T*& ptr)
{
    if (ptr)
    {
        ptr->Release();
        ptr = nullptr;
    }
}

// URL parsing utilities
HRESULT ParseURL(const std::wstring& url, std::wstring& protocol, std::wstring& host, 
                std::wstring& path, DWORD& port);

// Base64 encoding/decoding (if needed for authentication)
HRESULT Base64Encode(const BYTE* pData, DWORD cbData, std::wstring& encoded);
HRESULT Base64Decode(const std::wstring& encoded, std::vector<BYTE>& decoded);

// Password strength validation
BOOL IsPasswordStrong(PCWSTR pszPassword);

// Network utilities
HRESULT IsNetworkAvailable(BOOL* pbAvailable);
HRESULT TestEndpointConnectivity(const std::wstring& endpoint, BOOL* pbConnected);

// Biometric data processing
HRESULT ValidateKeystrokeData(const std::vector<KeystrokeData>& keystrokes, BOOL* pbValid);
HRESULT CalculateKeystrokeTiming(const std::vector<KeystrokeData>& keystrokes, 
                                DWORD* pdwAverageInterval, DWORD* pdwVariance);

// Debug utilities
#ifdef _DEBUG
void DebugPrint(PCWSTR pszFormat, ...);
void DebugPrintKeystrokeData(const std::vector<KeystrokeData>& keystrokes);
#else
#define DebugPrint(...)
#define DebugPrintKeystrokeData(...)
#endif

// String formatting utilities
HRESULT FormatString(PWSTR pszBuffer, size_t cchBuffer, PCWSTR pszFormat, ...);
HRESULT FormatStringV(PWSTR pszBuffer, size_t cchBuffer, PCWSTR pszFormat, va_list args);

// File utilities (for logging)
HRESULT WriteToLogFile(PCWSTR pszMessage);
HRESULT GetLogFilePath(std::wstring& logPath);

// Credential validation
HRESULT ValidateCredentials(PCWSTR pszUsername, PCWSTR pszPassword, PCWSTR pszDomain, BOOL* pbValid);

// System information
HRESULT GetSystemInfo(std::wstring& computerName, std::wstring& userName, std::wstring& domain);

// Thread safety utilities
class CriticalSectionWrapper
{
private:
    CRITICAL_SECTION m_cs;
    bool m_bInitialized;

public:
    CriticalSectionWrapper();
    ~CriticalSectionWrapper();
    
    HRESULT Initialize();
    void Enter();
    void Leave();
    bool TryEnter();
    bool IsInitialized() const { return m_bInitialized; }
};

// Event utilities
HRESULT CreateUniqueEvent(HANDLE* phEvent);
HRESULT WaitForEventWithTimeout(HANDLE hEvent, DWORD dwTimeout);

// Performance monitoring
class PerformanceTimer
{
private:
    LONGLONG m_frequency;
    LONGLONG m_startTime;
    
public:
    PerformanceTimer();
    void Start();
    DWORD GetElapsedMilliseconds();
    LONGLONG GetElapsedTicks();
};

// Constants for HTTP communication
#define HTTP_TIMEOUT_DEFAULT        30000
#define HTTP_TIMEOUT_CONNECT        10000
#define HTTP_TIMEOUT_SEND           20000
#define HTTP_TIMEOUT_RECEIVE        30000
#define HTTP_BUFFER_SIZE            8192
#define MAX_URL_LENGTH              2048
#define MAX_RESPONSE_SIZE           1048576  // 1MB

// Constants for keystroke analysis
#define MIN_KEYSTROKE_INTERVAL      10      // milliseconds
#define MAX_KEYSTROKE_INTERVAL      5000    // milliseconds
#define MIN_PASSWORD_LENGTH         1
#define MAX_PASSWORD_LENGTH         256

// Error codes
#define E_BIOMETRIC_INVALID_DATA    MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x1001)
#define E_BIOMETRIC_AI_FAILED       MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x1002)
#define E_BIOMETRIC_TIMEOUT         MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x1003)
#define E_BIOMETRIC_NETWORK_ERROR   MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x1004)
#define E_BIOMETRIC_AUTH_FAILED     MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x1005)