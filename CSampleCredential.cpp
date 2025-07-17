#include "CSampleCredential.h"
#include "guid.h"
#include "helpers.h"
#include "Dll.h"
#include <ntsecapi.h>
#include <lm.h>

CSampleCredential::CSampleCredential() :
    m_cRef(1),
    m_cpus(CPUS_INVALID),
    m_rgCredProvFieldDescriptors(nullptr),
    m_rgFieldStatePairs(nullptr),
    m_rgFieldStrings(nullptr),
    m_pCredProvUser(nullptr),
    m_pszUserSid(nullptr),
    m_pszUsername(nullptr),
    m_pszPassword(nullptr),
    m_pszDomain(nullptr),
    m_pCredProvCredentialEvents(nullptr),
    m_bBiometricCaptureActive(FALSE),
    m_bKeystrokeAnalysisComplete(FALSE),
    m_bAIAuthenticationPassed(FALSE),
    m_bFirstKeystroke(TRUE),
    m_dwTimeout(30000),
    m_bDebugMode(FALSE),
    m_bCriticalSectionInitialized(FALSE),
    m_bSelected(FALSE),
    m_bSubmitClicked(FALSE),
    m_ntsLastResult(STATUS_SUCCESS)
{
    DllAddRef();
    
    // Initialize critical section
    InitializeCriticalSection(&m_cs);
    m_bCriticalSectionInitialized = TRUE;
    
    // Initialize performance timer
    QueryPerformanceFrequency(&m_performanceFrequency);
    
    // Load configuration
    GetConfigurationValue(CONFIG_AI_ENDPOINT, m_strAIEndpoint);
    GetConfigurationValue(CONFIG_AI_API_KEY, m_strAPIKey);
    
    // Initialize biometric profile
    m_biometricProfile.keystrokes.clear();
    m_biometricProfile.password.clear();
    m_biometricProfile.totalTypingTime = 0;
    m_biometricProfile.passwordLength = 0;
}

CSampleCredential::~CSampleCredential()
{
    _SecureMemoryCleanup();
    
    if (m_pCredProvCredentialEvents)
    {
        m_pCredProvCredentialEvents->Release();
    }
    
    if (m_pCredProvUser)
    {
        m_pCredProvUser->Release();
    }
    
    // Clean up field strings
    if (m_rgFieldStrings)
    {
        for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
        {
            CoTaskMemFree(m_rgFieldStrings[i]);
        }
        delete[] m_rgFieldStrings;
    }
    
    // Clean up field descriptors
    if (m_rgCredProvFieldDescriptors)
    {
        for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
        {
            CoTaskMemFree(m_rgCredProvFieldDescriptors[i].pszLabel);
        }
        delete[] m_rgCredProvFieldDescriptors;
    }
    
    delete[] m_rgFieldStatePairs;
    
    CoTaskMemFree(m_pszUserSid);
    CoTaskMemFree(m_pszUsername);
    CoTaskMemFree(m_pszPassword);
    CoTaskMemFree(m_pszDomain);
    
    if (m_bCriticalSectionInitialized)
    {
        DeleteCriticalSection(&m_cs);
    }
    
    DllRelease();
}

// Critical SetStringValue implementation - captures keystrokes
STDMETHODIMP CSampleCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    HRESULT hr = S_OK;
    
    if (dwFieldID >= FID_NUM_FIELDS)
    {
        return E_INVALIDARG;
    }
    
    CAutoLock lock(&m_cs);
    
    // Store previous value for keystroke analysis
    PCWSTR pwzOldValue = m_rgFieldStrings[dwFieldID];
    
    // Update the field value
    CoTaskMemFree(m_rgFieldStrings[dwFieldID]);
    hr = SHStrDupW(pwz, &m_rgFieldStrings[dwFieldID]);
    
    // Capture keystroke data for password field
    if (SUCCEEDED(hr) && dwFieldID == FID_PASSWORD && m_bBiometricCaptureActive)
    {
        hr = _CaptureKeystroke(pwzOldValue, pwz);
    }
    
    return hr;
}

// Keystroke capture implementation
HRESULT CSampleCredential::_CaptureKeystroke(PCWSTR pwzOldValue, PCWSTR pwzNewValue)
{
    HRESULT hr = S_OK;
    LARGE_INTEGER currentTime;
    
    // Get high-resolution timestamp
    if (!QueryPerformanceCounter(&currentTime))
    {
        return GetLastErrorAsHRESULT();
    }
    
    // Initialize timing on first keystroke
    if (m_bFirstKeystroke)
    {
        m_firstKeystrokeTime = currentTime;
        m_lastKeystrokeTime = currentTime;
        m_bFirstKeystroke = FALSE;
        return S_OK;
    }
    
    // Analyze keystroke changes
    size_t oldLen = pwzOldValue ? wcslen(pwzOldValue) : 0;
    size_t newLen = pwzNewValue ? wcslen(pwzNewValue) : 0;
    
    if (newLen > oldLen)
    {
        // Key was pressed (character added)
        WCHAR newChar = pwzNewValue[newLen - 1];
        
        KeystrokeData keystroke;
        keystroke.key = newChar;
        keystroke.keyDownTime = currentTime.QuadPart;
        keystroke.keyUpTime = currentTime.QuadPart; // Approximate key up time
        keystroke.position = static_cast<DWORD>(newLen - 1);
        
        // Add to biometric profile
        m_biometricProfile.keystrokes.push_back(keystroke);
        m_biometricProfile.password = pwzNewValue;
        m_biometricProfile.passwordLength = static_cast<DWORD>(newLen);
        
        // Update status
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, FID_BIOMETRIC_STATUS, 
                                                       L"Capturing keystroke pattern...");
        }
    }
    else if (newLen < oldLen)
    {
        // Key was deleted (backspace)
        if (!m_biometricProfile.keystrokes.empty())
        {
            m_biometricProfile.keystrokes.pop_back();
        }
        m_biometricProfile.password = pwzNewValue;
        m_biometricProfile.passwordLength = static_cast<DWORD>(newLen);
    }
    
    // Update last keystroke time
    m_lastKeystrokeTime = currentTime;
    
    return hr;
}

// AI authentication implementation
HRESULT CSampleCredential::_SendBiometricDataToAI()
{
    HRESULT hr = S_OK;
    
    if (m_biometricProfile.keystrokes.empty())
    {
        return E_INVALIDARG;
    }
    
    // Create JSON payload
    std::wstring jsonData;
    hr = CreateJSONString(m_biometricProfile, jsonData);
    
    if (SUCCEEDED(hr))
    {
        // Send to AI model
        std::wstring response;
        hr = SendHTTPRequest(m_strAIEndpoint, jsonData, m_strAPIKey, response);
        
        if (SUCCEEDED(hr))
        {
            // Parse AI response
            hr = ParseJSONResponse(response, m_aiResponse);
            
            if (SUCCEEDED(hr))
            {
                m_bAIAuthenticationPassed = m_aiResponse.isLegitimate;
                
                // Update status based on AI response
                if (m_pCredProvCredentialEvents)
                {
                    PCWSTR statusText = m_bAIAuthenticationPassed ? 
                        L"Authentication successful" : 
                        L"Authentication failed - suspicious pattern detected";
                    
                    m_pCredProvCredentialEvents->SetFieldString(this, FID_BIOMETRIC_STATUS, statusText);
                }
            }
        }
    }
    
    return hr;
}

// GetSerialization - core authentication method
STDMETHODIMP CSampleCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    HRESULT hr = S_OK;
    
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    
    CAutoLock lock(&m_cs);
    
    // Process biometric data if available
    if (!m_biometricProfile.keystrokes.empty())
    {
        // Calculate total typing time
        if (m_biometricProfile.keystrokes.size() > 0)
        {
            m_biometricProfile.totalTypingTime = 
                m_biometricProfile.keystrokes.back().keyUpTime - 
                m_biometricProfile.keystrokes.front().keyDownTime;
        }
        
        // Send to AI model for authentication
        hr = _SendBiometricDataToAI();
        
        if (FAILED(hr))
        {
            SHStrDupW(L"AI authentication failed", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return hr;
        }
        
        // Check AI authentication result
        if (!m_bAIAuthenticationPassed)
        {
            SHStrDupW(L"Access denied - behavioral authentication failed", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return E_ACCESSDENIED;
        }
    }
    
    // Continue with standard credential serialization
    PWSTR pwzUsername = nullptr;
    PWSTR pwzPassword = nullptr;
    PWSTR pwzDomain = nullptr;
    
    hr = _GetUserCredentials(&pwzUsername, &pwzPassword, &pwzDomain);
    
    if (SUCCEEDED(hr))
    {
        hr = _PackageCredentials(pcpgsr, pcpcs);
        
        if (SUCCEEDED(hr))
        {
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
    }
    
    CoTaskMemFree(pwzUsername);
    CoTaskMemFree(pwzPassword);
    CoTaskMemFree(pwzDomain);
    
    return hr;
}

// Initialize credential
HRESULT CSampleCredential::Initialize(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    ICredentialProviderUser* pcpUser)
{
    HRESULT hr = S_OK;
    
    m_cpus = cpus;
    
    // Copy field descriptors
    m_rgCredProvFieldDescriptors = new CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR[FID_NUM_FIELDS];
    if (m_rgCredProvFieldDescriptors)
    {
        for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
        {
            m_rgCredProvFieldDescriptors[i] = rgcpfd[i];
            hr = SHStrDupW(rgcpfd[i].pszLabel, &m_rgCredProvFieldDescriptors[i].pszLabel);
            if (FAILED(hr))
            {
                break;
            }
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    // Copy field state pairs
    if (SUCCEEDED(hr))
    {
        m_rgFieldStatePairs = new FIELD_STATE_PAIR[FID_NUM_FIELDS];
        if (m_rgFieldStatePairs)
        {
            for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
            {
                m_rgFieldStatePairs[i] = rgfsp[i];
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    
    // Initialize field strings
    if (SUCCEEDED(hr))
    {
        m_rgFieldStrings = new PWSTR[FID_NUM_FIELDS];
        if (m_rgFieldStrings)
        {
            for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
            {
                hr = SHStrDupW(s_rgFieldStrings[i], &m_rgFieldStrings[i]);
                if (FAILED(hr))
                {
                    break;
                }
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    
    // Store user
    if (SUCCEEDED(hr) && pcpUser)
    {
        m_pCredProvUser = pcpUser;
        m_pCredProvUser->AddRef();
    }
    
    return hr;
}

// Start keystroke capture when selected
STDMETHODIMP CSampleCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    
    CAutoLock lock(&m_cs);
    
    m_bSelected = TRUE;
    m_bBiometricCaptureActive = TRUE;
    m_bFirstKeystroke = TRUE;
    
    // Clear previous biometric data
    _ResetBiometricData();
    
    return S_OK;
}

// Stop keystroke capture when deselected
STDMETHODIMP CSampleCredential::SetDeselected()
{
    CAutoLock lock(&m_cs);
    
    m_bSelected = FALSE;
    m_bBiometricCaptureActive = FALSE;
    
    return S_OK;
}

// Additional interface implementations...
STDMETHODIMP CSampleCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (ppv == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppv = nullptr;
    
    if (IsEqualIID(riid, IID_IUnknown) || 
        IsEqualIID(riid, IID_ICredentialProviderCredential) ||
        IsEqualIID(riid, IID_ICredentialProviderCredential2))
    {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
    }
    else if (IsEqualIID(riid, IID_ICredentialProviderCredentialEvents))
    {
        *ppv = static_cast<ICredentialProviderCredentialEvents*>(this);
    }
    else
    {
        return E_NOINTERFACE;
    }
    
    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) CSampleCredential::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CSampleCredential::Release()
{
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return cRef;
}

// Helper method implementations
HRESULT CSampleCredential::_ResetBiometricData()
{
    m_biometricProfile.keystrokes.clear();
    m_biometricProfile.password.clear();
    m_biometricProfile.totalTypingTime = 0;
    m_biometricProfile.passwordLength = 0;
    
    m_bKeystrokeAnalysisComplete = FALSE;
    m_bAIAuthenticationPassed = FALSE;
    
    return S_OK;
}

HRESULT CSampleCredential::_SecureMemoryCleanup()
{
    // Securely clear biometric data
    if (!m_biometricProfile.keystrokes.empty())
    {
        SecureZeroMemory(&m_biometricProfile.keystrokes[0], 
                        m_biometricProfile.keystrokes.size() * sizeof(KeystrokeData));
        m_biometricProfile.keystrokes.clear();
    }
    
    if (!m_biometricProfile.password.empty())
    {
        SecureZeroMemory(const_cast<PWSTR>(m_biometricProfile.password.c_str()),
                        m_biometricProfile.password.length() * sizeof(WCHAR));
        m_biometricProfile.password.clear();
    }
    
    return S_OK;
}

// Remaining interface methods would be implemented here...
// [Additional methods omitted for brevity]
