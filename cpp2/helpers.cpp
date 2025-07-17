#include "helpers.h"
#include <shlwapi.h>
#include <wininet.h>
#include <wincrypt.h>
#include <lm.h>
#include <sddl.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

// String conversion utilities
std::wstring AnsiToUnicode(const std::string& str)
{
    if (str.empty()) return std::wstring();
    
    int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 0) return std::wstring();
    
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &result[0], len);
    return result;
}

std::string UnicodeToAnsi(const std::wstring& str)
{
    if (str.empty()) return std::string();
    
    int len = WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::string UnicodeToUtf8(const std::wstring& str)
{
    if (str.empty()) return std::string();
    
    int len = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToUnicode(const std::string& str)
{
    if (str.empty()) return std::wstring();
    
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 0) return std::wstring();
    
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], len);
    return result;
}

// Configuration management
HRESULT GetConfigurationValue(PCWSTR pszValueName, std::wstring& value)
{
    HKEY hKey = nullptr;
    HRESULT hr = OpenRegistryKey(HKEY_LOCAL_MACHINE, BIOMETRIC_CONFIG_KEY, KEY_READ, &hKey);
    
    if (SUCCEEDED(hr))
    {
        hr = ReadRegistryString(hKey, pszValueName, value);
        RegCloseKey(hKey);
    }
    
    return hr;
}

HRESULT SetConfigurationValue(PCWSTR pszValueName, PCWSTR pszValue)
{
    HKEY hKey = nullptr;
    HRESULT hr = OpenRegistryKey(HKEY_LOCAL_MACHINE, BIOMETRIC_CONFIG_KEY, KEY_WRITE, &hKey);
    
    if (SUCCEEDED(hr))
    {
        hr = WriteRegistryString(hKey, pszValueName, pszValue);
        RegCloseKey(hKey);
    }
    
    return hr;
}

// Authentication package utilities
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
    HRESULT hr = S_OK;
    HANDLE hLsa = nullptr;
    
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        LSA_STRING lsaString;
        lsaString.Buffer = const_cast<PCHAR>(NEGOSSP_NAME_A);
        lsaString.Length = static_cast<USHORT>(strlen(NEGOSSP_NAME_A));
        lsaString.MaximumLength = lsaString.Length;
        
        status = LsaLookupAuthenticationPackage(hLsa, &lsaString, pulAuthPackage);
        hr = HRESULT_FROM_NT(status);
        
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr = HRESULT_FROM_NT(status);
    }
    
    return hr;
}

HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, PWSTR* ppwzProtectedPassword)
{
    HRESULT hr = S_OK;
    
    if (CPUS_CREDUI == cpus)
    {
        hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
    }
    else
    {
        // For other scenarios, we might need to protect the password
        DWORD cchPassword = static_cast<DWORD>(wcslen(pwzPassword));
        DWORD cbPassword = (cchPassword + 1) * sizeof(WCHAR);
        
        *ppwzProtectedPassword = static_cast<PWSTR>(CoTaskMemAlloc(cbPassword));
        if (*ppwzProtectedPassword)
        {
            hr = StringCchCopyW(*ppwzProtectedPassword, cchPassword + 1, pwzPassword);
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    
    return hr;
}

HRESULT SplitDomainAndUsername(PCWSTR pszQualifiedUserName, PWSTR* ppszDomain, PWSTR* ppszUsername)
{
    HRESULT hr = S_OK;
    
    *ppszDomain = nullptr;
    *ppszUsername = nullptr;
    
    PCWSTR pszDelimiter = wcschr(pszQualifiedUserName, L'\\');
    if (pszDelimiter)
    {
        // Domain\Username format
        size_t cchDomain = pszDelimiter - pszQualifiedUserName;
        size_t cchUsername = wcslen(pszDelimiter + 1);
        
        *ppszDomain = static_cast<PWSTR>(CoTaskMemAlloc((cchDomain + 1) * sizeof(WCHAR)));
        *ppszUsername = static_cast<PWSTR>(CoTaskMemAlloc((cchUsername + 1) * sizeof(WCHAR)));
        
        if (*ppszDomain && *ppszUsername)
        {
            hr = StringCchCopyNW(*ppszDomain, cchDomain + 1, pszQualifiedUserName, cchDomain);
            if (SUCCEEDED(hr))
            {
                hr = StringCchCopyW(*ppszUsername, cchUsername + 1, pszDelimiter + 1);
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        pszDelimiter = wcschr(pszQualifiedUserName, L'@');
        if (pszDelimiter)
        {
            // Username@Domain format
            size_t cchUsername = pszDelimiter - pszQualifiedUserName;
            size_t cchDomain = wcslen(pszDelimiter + 1);
            
            *ppszDomain = static_cast<PWSTR>(CoTaskMemAlloc((cchDomain + 1) * sizeof(WCHAR)));
            *ppszUsername = static_cast<PWSTR>(CoTaskMemAlloc((cchUsername + 1) * sizeof(WCHAR)));
            
            if (*ppszDomain && *ppszUsername)
            {
                hr = StringCchCopyNW(*ppszUsername, cchUsername + 1, pszQualifiedUserName, cchUsername);
                if (SUCCEEDED(hr))
                {
                    hr = StringCchCopyW(*ppszDomain, cchDomain + 1, pszDelimiter + 1);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
        else
        {
            // No domain specified, use local machine
            DWORD cchComputerName = 0;
            GetComputerNameW(nullptr, &cchComputerName);
            
            *ppszDomain = static_cast<PWSTR>(CoTaskMemAlloc(cchComputerName * sizeof(WCHAR)));
            hr = SHStrDupW(pszQualifiedUserName, ppszUsername);
            
            if (SUCCEEDED(hr) && *ppszDomain)
            {
                GetComputerNameW(*ppszDomain, &cchComputerName);
            }
        }
    }
    
    if (FAILED(hr))
    {
        CoTaskMemFree(*ppszDomain);
        CoTaskMemFree(*ppszUsername);
        *ppszDomain = nullptr;
        *ppszUsername = nullptr;
    }
    
    return hr;
}

// Kerberos authentication utilities
HRESULT KerbInteractiveUnlockLogonInit(PCWSTR pwzDomain, PCWSTR pwzUsername, PCWSTR pwzPassword, 
                                      CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
    HRESULT hr = S_OK;
    
    ZeroMemory(pkiul, sizeof(*pkiul));
    
    // Set the logon type
    pkiul->Logon.MessageType = KerbInteractiveLogon;
    
    // Calculate buffer sizes
    DWORD cbDomain = static_cast<DWORD>((wcslen(pwzDomain) + 1) * sizeof(WCHAR));
    DWORD cbUsername = static_cast<DWORD>((wcslen(pwzUsername) + 1) * sizeof(WCHAR));
    DWORD cbPassword = static_cast<DWORD>((wcslen(pwzPassword) + 1) * sizeof(WCHAR));
    
    BYTE* pbBuffer = reinterpret_cast<BYTE*>(pkiul) + sizeof(*pkiul);
    
    // Domain
    pkiul->Logon.LogonDomainName.Length = static_cast<USHORT>(cbDomain - sizeof(WCHAR));
    pkiul->Logon.LogonDomainName.MaximumLength = static_cast<USHORT>(cbDomain);
    pkiul->Logon.LogonDomainName.Buffer = reinterpret_cast<PWSTR>(pbBuffer);
    hr = StringCchCopyW(pkiul->Logon.LogonDomainName.Buffer, cbDomain / sizeof(WCHAR), pwzDomain);
    
    if (SUCCEEDED(hr))
    {
        pbBuffer += cbDomain;
        
        // Username
        pkiul->Logon.UserName.Length = static_cast<USHORT>(cbUsername - sizeof(WCHAR));
        pkiul->Logon.UserName.MaximumLength = static_cast<USHORT>(cbUsername);
        pkiul->Logon.UserName.Buffer = reinterpret_cast<PWSTR>(pbBuffer);
        hr = StringCchCopyW(pkiul->Logon.UserName.Buffer, cbUsername / sizeof(WCHAR), pwzUsername);
        
        if (SUCCEEDED(hr))
        {
            pbBuffer += cbUsername;
            
            // Password
            pkiul->Logon.Password.Length = static_cast<USHORT>(cbPassword - sizeof(WCHAR));
            pkiul->Logon.Password.MaximumLength = static_cast<USHORT>(cbPassword);
            pkiul->Logon.Password.Buffer = reinterpret_cast<PWSTR>(pbBuffer);
            hr = StringCchCopyW(pkiul->Logon.Password.Buffer, cbPassword / sizeof(WCHAR), pwzPassword);
        }
    }
    
    return hr;
}

HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& kiul, BYTE** ppbPackage, DWORD* pcbPackage)
{
    HRESULT hr = S_OK;
    
    // Calculate total size needed
    DWORD cbDomain = kiul.Logon.LogonDomainName.MaximumLength;
    DWORD cbUsername = kiul.Logon.UserName.MaximumLength;
    DWORD cbPassword = kiul.Logon.Password.MaximumLength;
    DWORD cbTotal = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbDomain + cbUsername + cbPassword;
    
    *ppbPackage = static_cast<BYTE*>(CoTaskMemAlloc(cbTotal));
    if (*ppbPackage)
    {
        *pcbPackage = cbTotal;
        
        // Copy the structure
        KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(*ppbPackage);
        *pkiul = kiul;
        
        // Update pointers to be relative to the package
        BYTE* pbBuffer = *ppbPackage + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
        
        // Domain
        pkiul->Logon.LogonDomainName.Buffer = reinterpret_cast<PWSTR>(pbBuffer);
        CopyMemory(pbBuffer, kiul.Logon.LogonDomainName.Buffer, cbDomain);
        pbBuffer += cbDomain;
        
        // Username
        pkiul->Logon.UserName.Buffer = reinterpret_cast<PWSTR>(pbBuffer);
        CopyMemory(pbBuffer, kiul.Logon.UserName.Buffer, cbUsername);
        pbBuffer += cbUsername;
        
        // Password
        pkiul->Logon.Password.Buffer = reinterpret_cast<PWSTR>(pbBuffer);
        CopyMemory(pbBuffer, kiul.Logon.Password.Buffer, cbPassword);
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}

// JSON utilities for AI communication
HRESULT CreateJSONString(const BiometricProfile& profile, std::wstring& jsonOutput)
{
    HRESULT hr = S_OK;
    
    try
    {
        std::wstring json = L"{";
        json += L"\"keystrokes\": [";
        
        for (size_t i = 0; i < profile.keystrokes.size(); ++i)
        {
            const KeystrokeData& keystroke = profile.keystrokes[i];
            
            json += L"{";
            json += L"\"key\": \"" + std::wstring(1, keystroke.key) + L"\",";
            json += L"\"keyDownTime\": " + std::to_wstring(keystroke.keyDownTime) + L",";
            json += L"\"keyUpTime\": " + std::to_wstring(keystroke.keyUpTime) + L",";
            json += L"\"position\": " + std::to_wstring(keystroke.position);
            json += L"}";
            
            if (i < profile.keystrokes.size() - 1)
            {
                json += L",";
            }
        }
        
        json += L"],";
        json += L"\"passwordLength\": " + std::to_wstring(profile.passwordLength) + L",";
        json += L"\"totalTypingTime\": " + std::to_wstring(profile.totalTypingTime) + L",";
        json += L"\"username\": \"" + profile.username + L"\",";
        json += L"\"timestamp\": " + std::to_wstring(GetTickCount64());
        json += L"}";
        
        jsonOutput = json;
    }
    catch (const std::exception&)
    {
        hr = E_FAIL;
    }
    
    return hr;
}

HRESULT ParseJSONResponse(const std::wstring& jsonResponse, AIResponse& response)
{
    HRESULT hr = S_OK;
    
    try
    {
        // Simple JSON parsing - in production, use a proper JSON library
        response.isLegitimate = (jsonResponse.find(L"\"legitimate\"") != std::wstring::npos ||
                               jsonResponse.find(L"\"isLegitimate\":true") != std::wstring::npos ||
                               jsonResponse.find(L"\"result\":\"legitimate\"") != std::wstring::npos);
        
        response.confidenceScore = 0.0;
        response.message = L"Parsed from AI response";
        response.sessionId = L"";
        
        // Extract confidence score if present
        size_t confPos = jsonResponse.find(L"\"confidence\":");
        if (confPos != std::wstring::npos)
        {
            size_t startPos = confPos + 13; // Skip "confidence":
            size_t endPos = jsonResponse.find_first_of(L",}", startPos);
            if (endPos != std::wstring::npos)
            {
                std::wstring confStr = jsonResponse.substr(startPos, endPos - startPos);
                response.confidenceScore = _wtof(confStr.c_str());
            }
        }
    }
    catch (const std::exception&)
    {
        hr = E_FAIL;
    }
    
    return hr;
}

// HTTP communication with AI model
HRESULT SendHTTPRequest(const std::wstring& endpoint, const std::wstring& jsonData, 
                       const std::wstring& apiKey, std::wstring& response)
{
    HRESULT hr = S_OK;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    try
    {
        // Initialize WinHTTP
        hSession = WinHttpOpen(L"BiometricCredentialProvider/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (hSession)
        {
            // Parse URL
            std::wstring protocol, host, path;
            DWORD port;
            hr = ParseURL(endpoint, protocol, host, path, port);
            
            if (SUCCEEDED(hr))
            {
                hConnect = WinHttpConnect(hSession, host.c_str(), static_cast<INTERNET_PORT>(port), 0);
                
                if (hConnect)
                {
                    DWORD flags = (protocol == L"https") ? WINHTTP_FLAG_SECURE : 0;
                    
                    hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
                                                nullptr, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
                    
                    if (hRequest)
                    {
                        // Set headers
                        std::wstring headers = L"Content-Type: application/json\r\n";
                        if (!apiKey.empty())
                        {
                            headers += L"Authorization: Bearer " + apiKey + L"\r\n";
                        }
                        
                        // Convert JSON to UTF-8
                        std::string jsonUtf8 = UnicodeToUtf8(jsonData);
                        
                        // Send request
                        if (WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                             const_cast<char*>(jsonUtf8.c_str()), static_cast<DWORD>(jsonUtf8.length()),
                                             static_cast<DWORD>(jsonUtf8.length()), 0))
                        {
                            if (WinHttpReceiveResponse(hRequest, nullptr))
                            {
                                // Read response
                                DWORD dwSize = 0;
                                std::string responseData;
                                
                                do
                                {
                                    dwSize = 0;
                                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                                        break;
                                    
                                    if (dwSize > 0)
                                    {
                                        std::vector<char> buffer(dwSize + 1);
                                        DWORD dwDownloaded = 0;
                                        
                                        if (WinHttpReadData(hRequest, &buffer[0], dwSize, &dwDownloaded))
                                        {
                                            buffer[dwDownloaded] = '\0';
                                            responseData += &buffer[0];
                                        }
                                    }
                                } while (dwSize > 0);
                                
                                // Convert response to wide string
                                response = Utf8ToUnicode(responseData);
                            }
                        }
                        
                        WinHttpCloseHandle(hRequest);
                    }
                    
                    WinHttpCloseHandle(hConnect);
                }
            }
            
            WinHttpCloseHandle(hSession);
        }
        
        if (response.empty())
        {
            hr = E_FAIL;
        }
    }
    catch (const std::exception&)
    {
        hr = E_FAIL;
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }
    
    return hr;
}

// Error handling utilities
HRESULT GetLastErrorAsHRESULT()
{
    DWORD dwError = GetLastError();
    return HRESULT_FROM_WIN32(dwError);
}

// Registry utilities
HRESULT OpenRegistryKey(HKEY hKeyParent, PCWSTR pszSubKey, DWORD dwDesiredAccess, HKEY* phKey)
{
    LONG lResult = RegCreateKeyExW(hKeyParent, pszSubKey, 0, nullptr, 0, dwDesiredAccess, nullptr, phKey, nullptr);
    return HRESULT_FROM_WIN32(lResult);
}

HRESULT ReadRegistryString(HKEY hKey, PCWSTR pszValueName, std::wstring& value)
{
    HRESULT hr = S_OK;
    DWORD dwType = REG_SZ;
    DWORD cbData = 0;
    
    // Get size
    LONG lResult = RegQueryValueExW(hKey, pszValueName, nullptr, &dwType, nullptr, &cbData);
    if (lResult == ERROR_SUCCESS && dwType == REG_SZ)
    {
        std::vector<WCHAR> buffer(cbData / sizeof(WCHAR));
        lResult = RegQueryValueExW(hKey, pszValueName, nullptr, &dwType, 
                                  reinterpret_cast<LPBYTE>(&buffer[0]), &cbData);
        if (lResult == ERROR_SUCCESS)
        {
            value = &buffer[0];
        }
    }
    
    if (lResult != ERROR_SUCCESS)
    {
        hr = HRESULT_FROM_WIN32(lResult);
    }
    
    return hr;
}

HRESULT WriteRegistryString(HKEY hKey, PCWSTR pszValueName, PCWSTR pszValue)
{
    DWORD cbData = static_cast<DWORD>((wcslen(pszValue) + 1) * sizeof(WCHAR));
    LONG lResult = RegSetValueExW(hKey, pszValueName, 0, REG_SZ, 
                                 reinterpret_cast<const BYTE*>(pszValue), cbData);
    return HRESULT_FROM_WIN32(lResult);
}

// URL parsing utilities
HRESULT ParseURL(const std::wstring& url, std::wstring& protocol, std::wstring& host, 
                std::wstring& path, DWORD& port)
{
    HRESULT hr = S_OK;
    
    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = -1;
    urlComp.dwHostNameLength = -1;
    urlComp.dwUrlPathLength = -1;
    
    if (WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp))
    {
        if (urlComp.nScheme == INTERNET_SCHEME_HTTPS)
        {
            protocol = L"https";
            port = (urlComp.nPort == 0) ? 443 : urlComp.nPort;
        }
        else if (urlComp.nScheme == INTERNET_SCHEME_HTTP)
        {
            protocol = L"http";
            port = (urlComp.nPort == 0) ? 80 : urlComp.nPort;
        }
        else
        {
            hr = E_INVALIDARG;
        }
        
        if (SUCCEEDED(hr))
        {
            host = std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength);
            path = std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        }
    }
    else
    {
        hr = GetLastErrorAsHRESULT();
    }
    
    return hr;
}

// Performance timer implementation
PerformanceTimer::PerformanceTimer()
{
    QueryPerformanceFrequency(reinterpret_cast<LARGE_INTEGER*>(&m_frequency));
    m_startTime = 0;
}

void PerformanceTimer::Start()
{
    QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&m_startTime));
}

DWORD PerformanceTimer::GetElapsedMilliseconds()
{
    LONGLONG currentTime;
    QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&currentTime));
    return static_cast<DWORD>((currentTime - m_startTime) * 1000 / m_frequency);
}

LONGLONG PerformanceTimer::GetElapsedTicks()
{
    LONGLONG currentTime;
    QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&currentTime));
    return currentTime - m_startTime;
}
