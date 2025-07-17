#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <winhttp.h>
#include <ntsecapi.h>
#include <vector>
#include <string>
#include <memory>

// Field IDs for the credential provider
enum FIELD_ID
{
    FID_LABEL = 0,
    FID_USERNAME = 1,
    FID_PASSWORD = 2,
    FID_SUBMIT_BUTTON = 3,
    FID_BIOMETRIC_STATUS = 4,
    FID_NUM_FIELDS = 5
};

// Structure for capturing keystroke data
struct KeystrokeData
{
    WCHAR key;                 // The key pressed
    LONGLONG keyDownTime;      // High precision timestamp when key was pressed
    LONGLONG keyUpTime;        // High precision timestamp when key was released
    DWORD position;            // Position in the password string
};

// Biometric profile structure
struct BiometricProfile
{
    std::vector<KeystrokeData> keystrokes;
    std::wstring username;
    std::wstring password;
    LONGLONG startTime;
    LONGLONG totalTypingTime;
    DWORD passwordLength;
    LONGLONG performanceFrequency;
};

// AI Model Response structure
struct AIResponse
{
    bool isLegitimate;
    double confidenceScore;
    std::wstring message;
    std::wstring sessionId;
};

// Configuration constants
#define CONFIG_AI_ENDPOINT      L"AIEndpoint"
#define CONFIG_AI_API_KEY       L"APIKey"
#define CONFIG_TIMEOUT          L"Timeout"
#define CONFIG_ENABLED          L"Enabled"
#define CONFIG_DEBUG_MODE       L"DebugMode"

// Registry key for configuration
#define BIOMETRIC_CONFIG_KEY    L"SOFTWARE\\BiometricCredentialProvider"

// Default values
#define DEFAULT_TIMEOUT         30000
#define DEFAULT_AI_ENDPOINT     L"https://your-ai-model.com/api/authenticate"
#define DEFAULT_API_KEY         L"your-api-key-here"

// Helper macros
#define SAFE_RELEASE(p) { if (p) { (p)->Release(); (p) = nullptr; } }
#define SAFE_DELETE(p) { delete (p); (p) = nullptr; }
#define SAFE_DELETE_ARRAY(p) { delete[] (p); (p) = nullptr; }

// Auto-lock helper class
class CAutoLock
{
private:
    CRITICAL_SECTION* m_pcs;
    
public:
    CAutoLock(CRITICAL_SECTION* pcs) : m_pcs(pcs)
    {
        if (m_pcs)
        {
            EnterCriticalSection(m_pcs);
        }
    }
    
    ~CAutoLock()
    {
        if (m_pcs)
        {
            LeaveCriticalSection(m_pcs);
        }
    }
};

// Error handling macros
#define RETURN_IF_FAILED(hr) { if (FAILED(hr)) return hr; }
#define BREAK_IF_FAILED(hr) { if (FAILED(hr)) break; }

// Secure string handling
inline HRESULT SecureStringCopy(PWSTR pszDest, size_t cchDest, PCWSTR pszSrc)
{
    return StringCchCopyW(pszDest, cchDest, pszSrc);
}

inline HRESULT SecureStringCat(PWSTR pszDest, size_t cchDest, PCWSTR pszSrc)
{
    return StringCchCatW(pszDest, cchDest, pszSrc);
}

// High-resolution timer utilities
inline LONGLONG GetHighResolutionTime()
{
    LARGE_INTEGER time;
    QueryPerformanceCounter(&time);
    return time.QuadPart;
}

inline LONGLONG GetPerformanceFrequency()
{
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    return frequency.QuadPart;
}

// Convert performance counter to milliseconds
inline DWORD ConvertToMilliseconds(LONGLONG start, LONGLONG end, LONGLONG frequency)
{
    return static_cast<DWORD>((end - start) * 1000 / frequency);
}

// Secure memory cleanup
inline void SecureMemoryCleanup(void* ptr, size_t size)
{
    if (ptr)
    {
        SecureZeroMemory(ptr, size);
    }
}

// Field descriptors
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { FID_LABEL,            CPFT_SMALL_TEXT,        L"Biometric Authentication", CPFG_LOGON_USERNAME },
    { FID_USERNAME,         CPFT_EDIT_TEXT,         L"Username",                  CPFG_LOGON_USERNAME },
    { FID_PASSWORD,         CPFT_PASSWORD_TEXT,     L"Password",                  CPFG_LOGON_PASSWORD },
    { FID_SUBMIT_BUTTON,    CPFT_SUBMIT_BUTTON,     L"Sign in",                   CPFG_LOGON_SUBMIT },
    { FID_BIOMETRIC_STATUS, CPFT_SMALL_TEXT,        L"Ready for authentication",  CPFG_LOGON_USERNAME }
};

// Field state pairs
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE,    CPFIS_NONE },      // FID_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE,    CPFIS_FOCUSED },   // FID_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE,    CPFIS_NONE },      // FID_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,    CPFIS_NONE },      // FID_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,    CPFIS_NONE }       // FID_BIOMETRIC_STATUS
};

// Default field strings
static PCWSTR s_rgFieldStrings[] =
{
    L"Biometric Authentication",     // FID_LABEL
    L"",                            // FID_USERNAME
    L"",                            // FID_PASSWORD
    L"Sign in",                     // FID_SUBMIT_BUTTON
    L"Ready for authentication"     // FID_BIOMETRIC_STATUS
};

// Utility functions
HRESULT GetLastErrorAsHRESULT();
HRESULT GetConfigurationValue(PCWSTR pszValueName, std::wstring& value);
HRESULT SetConfigurationValue(PCWSTR pszValueName, PCWSTR pszValue);
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);
HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, PWSTR* ppwzProtectedPassword);
HRESULT SplitDomainAndUsername(PCWSTR pszQualifiedUserName, PWSTR* ppszDomain, PWSTR* ppszUsername);