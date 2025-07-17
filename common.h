#pragma once

#include <windows.h>
#include <strsafe.h>
#include <credentialprovider.h>
#include <ntstatus.h>
#include <winhttp.h>
#include <vector>
#include <string>
#include <memory>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

// Forward declarations
class CSampleCredential;
class CSampleProvider;

// Field IDs for credential provider
enum FIELD_ID 
{
    FID_LABEL = 0,
    FID_LARGE_TEXT = 1,
    FID_PASSWORD = 2,
    FID_SUBMIT_BUTTON = 3,
    FID_BIOMETRIC_STATUS = 4,
    FID_NUM_FIELDS
};

// Keystroke data structure
struct KeystrokeData
{
    WCHAR key;
    LONGLONG keyDownTime;
    LONGLONG keyUpTime;
    DWORD position;
};

// Biometric profile structure
struct BiometricProfile
{
    std::vector<KeystrokeData> keystrokes;
    std::wstring password;
    LONGLONG totalTypingTime;
    DWORD passwordLength;
};

// AI Response structure
struct AIResponse
{
    bool isLegitimate;
    double confidence;
    std::wstring message;
};

// Field descriptors
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { FID_LABEL, CPFT_SMALL_TEXT, L"Biometric Authentication", CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_LARGE_TEXT, CPFT_LARGE_TEXT, L"Enhanced Security Login", CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_PASSWORD, CPFT_PASSWORD_TEXT, L"Password", CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Sign in", CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_BIOMETRIC_STATUS, CPFT_SMALL_TEXT, L"Analyzing typing pattern...", CPFG_CREDENTIAL_PROVIDER_LABEL }
};

// Field state pairs
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
    { CPFS_HIDDEN, CPFIS_NONE }
};

// Field strings
static PWSTR s_rgFieldStrings[] = 
{
    L"Biometric Authentication",
    L"Enhanced Security Login",
    L"",
    L"Sign in",
    L"Analyzing typing pattern..."
};

// Configuration constants
const WCHAR* const AI_MODEL_ENDPOINT = L"https://your-ai-model-endpoint.com/authenticate";
const WCHAR* const AI_API_KEY = L"your-api-key-here";
const DWORD KEYSTROKE_BUFFER_SIZE = 256;
const DWORD HTTP_TIMEOUT = 30000; // 30 seconds

// Utility functions
HRESULT GetHighResolutionTime(LARGE_INTEGER* pTime);
DWORD CalculateTimeDifference(const LARGE_INTEGER& start, const LARGE_INTEGER& end);
HRESULT SecureZeroMemoryBuffer(PVOID buffer, SIZE_T size);
HRESULT CreateJSONFromBiometricData(const BiometricProfile& profile, std::wstring& jsonOutput);
HRESULT ParseAIResponse(const std::wstring& response, AIResponse& aiResponse);
HRESULT SendHTTPSRequest(const std::wstring& endpoint, const std::wstring& data, std::wstring& response);

// Global reference counter
extern LONG g_cRef;

// DLL instance
extern HINSTANCE g_hInst;

// Performance frequency for high-resolution timing
extern LARGE_INTEGER g_PerformanceFrequency;