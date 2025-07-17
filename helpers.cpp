#include "helpers.h"
#include <sstream>
#include <iomanip>
#include <wincrypt.h>

LARGE_INTEGER g_PerformanceFrequency = {0};
CRITICAL_SECTION g_CriticalSection;
BOOL g_bInitialized = FALSE;

// String conversion utilities
std::wstring AnsiToUnicode(const std::string& str)
{
    if (str.empty()) return std::wstring();
    
    int length = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (length == 0) return std::wstring();
    
    std::wstring result(length - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &result[0], length);
    return result;
}

std::string UnicodeToAnsi(const std::wstring& str)
{
    if (str.empty()) return std::string();
    
    int length = WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (length == 0) return std::string();
    
    std::string result(length - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, &result[0], length, nullptr, nullptr);
    return result;
}

std::string UnicodeToUtf8(const std::wstring& str)
{
    if (str.empty()) return std::string();
    
    int length = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (length == 0) return std::string();
    
    std::string result(length - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &result[0], length, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToUnicode(const std::string& str)
{
    if (str.empty()) return std::wstring();
    
    int length = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (length == 0) return std::wstring();
    
    std::wstring result(length - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], length);
    return result;
}

// Memory management utilities
HRESULT SecureAllocateMemory(SIZE_T size, PVOID* ppBuffer)
{
    if (!ppBuffer) return E_INVALIDARG;
    
    *ppBuffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*ppBuffer) return E_OUTOFMEMORY;
    
    if (!VirtualLock(*ppBuffer, size))
    {
        VirtualFree(*ppBuffer, 0, MEM_RELEASE);
        *ppBuffer = nullptr;
        return E_FAIL;
    }
    
    return S_OK;
}

HRESULT SecureFreeMemory(PVOID buffer, SIZE_T size)
{
    if (!buffer) return S_OK;
    
    SecureZeroMemory(buffer, size);
    VirtualUnlock(buffer, size);
    VirtualFree(buffer, 0, MEM_RELEASE);
    
    return S_OK;
}

HRESULT SecureStringCopy(PWSTR pszDest, SIZE_T cchDest, PCWSTR pszSrc)
{
    return StringCchCopyW(pszDest, cchDest, pszSrc);
}

// High-resolution timing utilities
HRESULT InitializePerformanceTimer()
{
    if (!g_bInitialized)
    {
        InitializeCriticalSection(&g_CriticalSection);
        
        if (!QueryPerformanceFrequency(&g_PerformanceFrequency))
        {
            return GetLastErrorAsHRESULT();
        }
        
        g_bInitialized = TRUE;
    }
    
    return S_OK;
}

HRESULT GetCurrentTimeStamp(LARGE_INTEGER* pTimeStamp)
{
    if (!pTimeStamp) return E_INVALIDARG;
    
    if (!QueryPerformanceCounter(pTimeStamp))
    {
        return GetLastErrorAsHRESULT();
    }
    
    return S_OK;
}

DWORD CalculateElapsedTime(const LARGE_INTEGER& start, const LARGE_INTEGER& end)
{
    if (g_PerformanceFrequency.QuadPart == 0) return 0;
    
    LONGLONG elapsed = end.QuadPart - start.QuadPart;
    return (DWORD)((elapsed * 1000) / g_PerformanceFrequency.QuadPart);
}

// Keystroke analysis utilities
HRESULT CaptureKeystrokeEvent(WCHAR key, LONGLONG timestamp, DWORD position, KeystrokeData& keystroke)
{
    keystroke.key = key;
    keystroke.keyDownTime = timestamp;
    keystroke.keyUpTime = timestamp; // Will be updated when key is released
    keystroke.position = position;
    
    return S_OK;
}

HRESULT AnalyzeKeystrokePattern(const std::vector<KeystrokeData>& keystrokes, BiometricProfile& profile)
{
    if (keystrokes.empty()) return E_INVALIDARG;
    
    profile.keystrokes = keystrokes;
    profile.passwordLength = static_cast<DWORD>(keystrokes.size());
    
    if (keystrokes.size() > 0)
    {
        profile.totalTypingTime = keystrokes.back().keyUpTime - keystrokes.front().keyDownTime;
    }
    
    return S_OK;
}

HRESULT ValidateKeystrokeData(const KeystrokeData& keystroke)
{
    if (keystroke.key == 0) return E_INVALIDARG;
    if (keystroke.keyDownTime <= 0) return E_INVALIDARG;
    if (keystroke.keyUpTime < keystroke.keyDownTime) return E_INVALIDARG;
    
    return S_OK;
}

// JSON utilities
HRESULT CreateJSONString(const BiometricProfile& profile, std::wstring& jsonOutput)
{
    try
    {
        std::wstringstream json;
        json << L"{";
        json << L"\"keystrokes\":[";
        
        for (size_t i = 0; i < profile.keystrokes.size(); ++i)
        {
            const KeystrokeData& keystroke = profile.keystrokes[i];
            
            json << L"{";
            json << L"\"key\":\"" << keystroke.key << L"\",";
            json << L"\"keyDownTime\":" << keystroke.keyDownTime << L",";
            json << L"\"keyUpTime\":" << keystroke.keyUpTime << L",";
            json << L"\"position\":" << keystroke.position;
            json << L"}";
            
            if (i < profile.keystrokes.size() - 1)
            {
                json << L",";
            }
        }
        
        json << L"],";
        json << L"\"passwordLength\":" << profile.passwordLength << L",";
        json << L"\"totalTypingTime\":" << profile.totalTypingTime;
        json << L"}";
        
        jsonOutput = json.str();
        return S_OK;
    }
    catch (...)
    {
        return E_FAIL;
    }
}

HRESULT ParseJSONResponse(const std::wstring& jsonInput, AIResponse& response)
{
    // Simple JSON parsing - in production, use a proper JSON library
    response.isLegitimate = (jsonInput.find(L"legitimate") != std::wstring::npos);
    response.confidence = 0.5; // Default confidence
    response.message = L"Authentication processed";
    
    // Extract confidence if present
    size_t confPos = jsonInput.find(L"\"confidence\":");
    if (confPos != std::wstring::npos)
    {
        size_t startPos = confPos + 13; // Length of "confidence":
        size_t endPos = jsonInput.find(L",", startPos);
        if (endPos == std::wstring::npos) endPos = jsonInput.find(L"}", startPos);
        
        if (endPos != std::wstring::npos)
        {
            std::wstring confStr = jsonInput.substr(startPos, endPos - startPos);
            response.confidence = _wtof(confStr.c_str());
        }
    }
    
    return S_OK;
}

HRESULT EscapeJSONString(const std::wstring& input, std::wstring& output)
{
    output.clear();
    output.reserve(input.length() * 2);
    
    for (wchar_t c : input)
    {
        switch (c)
        {
            case L'"': output += L"\\\""; break;
            case L'\\': output += L"\\\\"; break;
            case L'\b': output += L"\\b"; break;
            case L'\f': output += L"\\f"; break;
            case L'\n': output += L"\\n"; break;
            case L'\r': output += L"\\r"; break;
            case L'\t': output += L"\\t"; break;
            default: output += c; break;
        }
    }
    
    return S_OK;
}

// HTTP/HTTPS utilities
HRESULT InitializeWinHTTP()
{
    return S_OK; // WinHTTP is initialized per-request
}

HRESULT CleanupWinHTTP()
{
    return S_OK; // WinHTTP is cleaned up per-request
}

HRESULT SendHTTPRequest(const std::wstring& endpoint, const std::wstring& data, const std::wstring& apiKey, std::wstring& response)
{
    HRESULT hr = S_OK;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    try
    {
        // Parse URL
        URL_COMPONENTS urlComponents = {0};
        urlComponents.dwStructSize = sizeof(urlComponents);
        urlComponents.dwSchemeLength = -1;
        urlComponents.dwHostNameLength = -1;
        urlComponents.dwUrlPathLength = -1;
        urlComponents.dwExtraInfoLength = -1;
        
        if (!WinHttpCrackUrl(endpoint.c_str(), 0, 0, &urlComponents))
        {
            return GetLastErrorAsHRESULT();
        }
        
        // Initialize WinHTTP
        hSession = WinHttpOpen(L"BiometricCredentialProvider/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS,
                              0);
        
        if (!hSession)
        {
            return GetLastErrorAsHRESULT();
        }
        
        // Connect to server
        std::wstring hostname(urlComponents.lpszHostName, urlComponents.dwHostNameLength);
        hConnect = WinHttpConnect(hSession, hostname.c_str(), urlComponents.nPort, 0);
        
        if (!hConnect)
        {
            hr = GetLastErrorAsHRESULT();
            goto cleanup;
        }
        
        // Create request
        std::wstring urlPath(urlComponents.lpszUrlPath, urlComponents.dwUrlPathLength);
        DWORD flags = (urlComponents.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        
        hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath.c_str(),
                                     nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     flags);
        
        if (!hRequest)
        {
            hr = GetLastErrorAsHRESULT();
            goto cleanup;
        }
        
        // Set headers
        std::wstring headers = L"Content-Type: application/json\r\n";
        if (!apiKey.empty())
        {
            headers += L"Authorization: Bearer " + apiKey + L"\r\n";
        }
        
        // Convert data to UTF-8
        std::string utf8Data = UnicodeToUtf8(data);
        
        // Send request
        if (!WinHttpSendRequest(hRequest, headers.c_str(), -1,
                               (LPVOID)utf8Data.c_str(), utf8Data.length(),
                               utf8Data.length(), 0))
        {
            hr = GetLastErrorAsHRESULT();
            goto cleanup;
        }
        
        // Receive response
        if (!WinHttpReceiveResponse(hRequest, nullptr))
        {
            hr = GetLastErrorAsHRESULT();
            goto cleanup;
        }
        
        // Read response data
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        std::string responseData;
        
        do
        {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                hr = GetLastErrorAsHRESULT();
                goto cleanup;
            }
            
            if (dwSize > 0)
            {
                char* buffer = new char[dwSize + 1];
                if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded))
                {
                    buffer[dwDownloaded] = '\0';
                    responseData += buffer;
                }
                delete[] buffer;
            }
        } while (dwSize > 0);
        
        // Convert response to Unicode
        response = Utf8ToUnicode(responseData);
        
    cleanup:
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
        
        return hr;
    }
    catch (...)
    {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
        return E_FAIL;
    }
}

HRESULT ConfigureHTTPS(HINTERNET hRequest)
{
    // Configure HTTPS options
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags)))
    {
        return GetLastErrorAsHRESULT();
    }
    
    return S_OK;
}

// Error handling utilities
HRESULT LogError(const std::wstring& message, HRESULT hr)
{
    OutputDebugInfo(L"Error: " + message + L" (HRESULT: 0x" + std::to_wstring(hr) + L")");
    return hr;
}

HRESULT GetLastErrorAsHRESULT()
{
    DWORD dwError = GetLastError();
    return HRESULT_FROM_WIN32(dwError);
}

void OutputDebugInfo(const std::wstring& message)
{
    OutputDebugStringW((message + L"\n").c_str());
}

// Registry utilities
HRESULT ReadRegistryString(HKEY hKey, PCWSTR pszValueName, std::wstring& value)
{
    DWORD dwType = REG_SZ;
    DWORD dwSize = 0;
    
    LONG result = RegQueryValueExW(hKey, pszValueName, nullptr, &dwType, nullptr, &dwSize);
    if (result != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(result);
    }
    
    value.resize(dwSize / sizeof(WCHAR));
    result = RegQueryValueExW(hKey, pszValueName, nullptr, &dwType, (LPBYTE)&value[0], &dwSize);
    
    if (result == ERROR_SUCCESS)
    {
        // Remove null terminator if present
        if (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
    }
    
    return HRESULT_FROM_WIN32(result);
}

HRESULT WriteRegistryString(HKEY hKey, PCWSTR pszValueName, const std::wstring& value)
{
    LONG result = RegSetValueExW(hKey, pszValueName, 0, REG_SZ,
                                (CONST BYTE*)value.c_str(),
                                (value.length() + 1) * sizeof(WCHAR));
    
    return HRESULT_FROM_WIN32(result);
}

// Cryptographic utilities
HRESULT GenerateRandomBytes(PBYTE buffer, DWORD size)
{
    HCRYPTPROV hProv = 0;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return GetLastErrorAsHRESULT();
    }
    
    BOOL result = CryptGenRandom(hProv, size, buffer);
    HRESULT hr = result ? S_OK : GetLastErrorAsHRESULT();
    
    CryptReleaseContext(hProv, 0);
    return hr;
}

HRESULT HashData(PBYTE data, DWORD dataSize, PBYTE hash, DWORD hashSize)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HRESULT hr = S_OK;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return GetLastErrorAsHRESULT();
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        hr = GetLastErrorAsHRESULT();
        goto cleanup;
    }
    
    if (!CryptHashData(hHash, data, dataSize, 0))
    {
        hr = GetLastErrorAsHRESULT();
        goto cleanup;
    }
    
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        hr = GetLastErrorAsHRESULT();
        goto cleanup;
    }
    
cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return hr;
}

// Validation utilities
BOOL IsValidPasswordLength(DWORD length)
{
    return (length >= 1 && length <= MAX_PASSWORD_LENGTH);
}

BOOL IsValidKeystrokeTiming(LONGLONG downTime, LONGLONG upTime)
{
    return (downTime > 0 && upTime >= downTime);
}

BOOL IsValidEndpoint(const std::wstring& endpoint)
{
    return (endpoint.length() > 8 && endpoint.length() < MAX_ENDPOINT_LENGTH &&
            (endpoint.substr(0, 8) == L"https://"));
}