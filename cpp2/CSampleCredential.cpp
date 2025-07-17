#include "CSampleCredential.h"
#include "guid.h"
#include "Dll.h"
#include <ntsecapi.h>
#include <lm.h>
#include <shlwapi.h>

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
    m_bFirstKeystroke(TRUE),
    m_bKeystrokeAnalysisComplete(FALSE),
    m_bAIAuthenticationPassed(FALSE),
    m_dwTimeout(DEFAULT_TIMEOUT),
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
    m_performanceFrequency = GetPerformanceFrequency();
    
    // Load configuration
    LoadConfiguration();
    
    // Initialize biometric profile
    m_biometricProfile.keystrokes.clear();
    m_biometricProfile.username.clear();
    m_biometricProfile.password.clear();
    m_biometricProfile.totalTypingTime = 0;
    m_biometricProfile.passwordLength = 0;
    m_biometricProfile.performanceFrequency = m_performanceFrequency;
}

CSampleCredential::~CSampleCredential()
{
    SecureMemoryCleanup();
    
    SAFE_RELEASE(m_pCredProvCredentialEvents);
    SAFE_RELEASE(m_pCredProvUser);
    
    // Clean up field strings
    if (m_rgFieldStrings)
    {
        for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
        {
            CoTaskMemFree(m_rgFieldStrings[i]);
        }
        SAFE_DELETE_ARRAY(m_rgFieldStrings);
    }
    
    // Clean up field descriptors
    if (m_rgCredProvFieldDescriptors)
    {
        for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
        {
            CoTaskMemFree(m_rgCredProvFieldDescriptors[i].pszLabel);
        }
        SAFE_DELETE_ARRAY(m_rgCredProvFieldDescriptors);
    }
    
    SAFE_DELETE_ARRAY(m_rgFieldStatePairs);
    
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

// IUnknown implementation
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
    else
    {
        return E_NOINTERFACE;
    }
    
    AddRef();
    return S_OK;
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
        hr = CaptureKeystrokeTiming(pwzOldValue, pwz);
    }
    
    return hr;
}

// Keystroke capture implementation
HRESULT CSampleCredential::CaptureKeystrokeTiming(PCWSTR pwzOldValue, PCWSTR pwzNewValue)
{
    HRESULT hr = S_OK;
    LONGLONG currentTime = GetHighResolutionTime();
    
    // Initialize timing on first keystroke
    if (m_bFirstKeystroke)
    {
        m_firstKeystrokeTime = currentTime;
        m_lastKeystrokeTime = currentTime;
        m_biometricProfile.startTime = currentTime;
        m_bFirstKeystroke = FALSE;
        
        // Update status
        UpdateStatusText(L"Capturing keystroke pattern...");
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
        keystroke.keyDownTime = currentTime;
        keystroke.keyUpTime = currentTime; // Approximation - actual implementation would need key hook
        keystroke.position = static_cast<DWORD>(newLen - 1);
        
        // Add to biometric profile
        m_biometricProfile.keystrokes.push_back(keystroke);
        m_biometricProfile.password = pwzNewValue;
        m_biometricProfile.passwordLength = static_cast<DWORD>(newLen);
        
        // Update status
        WCHAR statusText[256];
        StringCchPrintfW(statusText, ARRAYSIZE(statusText), 
                        L"Captured %d keystrokes...", 
                        static_cast<int>(m_biometricProfile.keystrokes.size()));
        UpdateStatusText(statusText);
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

// Two-stage authentication implementation
STDMETHODIMP CSampleCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    HRESULT hr = S_OK;
    
    // Initialize output parameters
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    
    CAutoLock lock(&m_cs);
    
    // STAGE 1: Windows Authentication with KerbInteractiveUnlockLogonPack
    UpdateStatusText(L"Validating Windows credentials...");
    
    PWSTR pwzProtectedPassword = nullptr;
    hr = ProtectIfNecessaryAndCopyPassword(m_rgFieldStrings[FID_PASSWORD], m_cpus, &pwzProtectedPassword);
    
    if (SUCCEEDED(hr))
    {
        PWSTR pszDomain = nullptr;
        PWSTR pszUsername = nullptr;
        
        // Split domain and username if needed
        hr = SplitDomainAndUsername(m_rgFieldStrings[FID_USERNAME], &pszDomain, &pszUsername);
        
        if (SUCCEEDED(hr))
        {
            // Initialize Kerberos structure
            const DWORD cbKiul = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 
                                 (wcslen(pszDomain) + 1) * sizeof(WCHAR) +
                                 (wcslen(pszUsername) + 1) * sizeof(WCHAR) +
                                 (wcslen(pwzProtectedPassword) + 1) * sizeof(WCHAR);
            
            KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(
                LocalAlloc(LMEM_ZEROINIT, cbKiul));
            
            if (pkiul)
            {
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, m_cpus, pkiul);
                
                if (SUCCEEDED(hr))
                {
                    // Pack the credentials for Windows authentication
                    BYTE* prgbSerialization = nullptr;
                    DWORD cbSerialization = 0;
                    
                    hr = KerbInteractiveUnlockLogonPack(*pkiul, &prgbSerialization, &cbSerialization);
                    
                    if (SUCCEEDED(hr))
                    {
                        // Get authentication package
                        ULONG ulAuthPackage = 0;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        
                        if (SUCCEEDED(hr))
                        {
                            // At this point, Windows authentication structure is ready
                            // Now proceed to STAGE 2: AI Model Authentication
                            UpdateStatusText(L"Analyzing behavioral biometrics...");
                            
                            bool bAIAuthenticationPassed = false;
                            
                            // Check if we have captured keystroke data
                            if (!m_biometricProfile.keystrokes.empty())
                            {
                                // Update biometric profile with current credentials
                                m_biometricProfile.username = pszUsername;
                                
                                // Calculate total typing time
                                if (m_biometricProfile.keystrokes.size() > 1)
                                {
                                    m_biometricProfile.totalTypingTime = 
                                        m_biometricProfile.keystrokes.back().keyUpTime - 
                                        m_biometricProfile.keystrokes.front().keyDownTime;
                                }
                                
                                // Send keystroke data to AI model
                                hr = SendBiometricDataToAI(&bAIAuthenticationPassed);
                                
                                if (FAILED(hr))
                                {
                                    // AI communication failed
                                    SHStrDupW(L"Biometric authentication service unavailable", ppwszOptionalStatusText);
                                    *pcpsiOptionalStatusIcon = CPSI_ERROR;
                                }
                                else if (!bAIAuthenticationPassed)
                                {
                                    // AI rejected the keystroke pattern
                                    SHStrDupW(L"Access denied - typing pattern verification failed", ppwszOptionalStatusText);
                                    *pcpsiOptionalStatusIcon = CPSI_ERROR;
                                    hr = E_ACCESSDENIED;
                                }
                                else
                                {
                                    UpdateStatusText(L"Biometric authentication successful");
                                }
                            }
                            else
                            {
                                // No keystroke data captured
                                SHStrDupW(L"No behavioral data captured", ppwszOptionalStatusText);
                                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                                hr = E_INVALIDARG;
                            }
                            
                            // Only proceed if both authentications succeeded
                            if (SUCCEEDED(hr) && bAIAuthenticationPassed)
                            {
                                // Both Windows and AI authentication succeeded
                                pcpcs->ulAuthenticationPackage = ulAuthPackage;
                                pcpcs->clsidCredentialProvider = CLSID_CSample;
                                pcpcs->cbSerialization = cbSerialization;
                                pcpcs->rgbSerialization = prgbSerialization;
                                
                                // Success - allow user to enter system
                                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                                SHStrDupW(L"Authentication successful", ppwszOptionalStatusText);
                                *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
                                
                                // Don't free the serialization buffer - it's now owned by the system
                                prgbSerialization = nullptr;
                                
                                UpdateStatusText(L"Login successful");
                            }
                            else
                            {
                                // Clean up serialization buffer on failure
                                CoTaskMemFree(prgbSerialization);
                            }
                        }
                        else
                        {
                            CoTaskMemFree(prgbSerialization);
                            SHStrDupW(L"Authentication package not available", ppwszOptionalStatusText);
                            *pcpsiOptionalStatusIcon = CPSI_ERROR;
                        }
                    }
                    else
                    {
                        SHStrDupW(L"Failed to package credentials", ppwszOptionalStatusText);
                        *pcpsiOptionalStatusIcon = CPSI_ERROR;
                    }
                }
                else
                {
                    SHStrDupW(L"Failed to initialize authentication", ppwszOptionalStatusText);
                    *pcpsiOptionalStatusIcon = CPSI_ERROR;
                }
                
                LocalFree(pkiul);
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
            
            CoTaskMemFree(pszDomain);
            CoTaskMemFree(pszUsername);
        }
        else
        {
            SHStrDupW(L"Invalid username format", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
        
        CoTaskMemFree(pwzProtectedPassword);
    }
    else
    {
        SHStrDupW(L"Failed to process password", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    
    return hr;
}

// AI model communication
HRESULT CSampleCredential::SendBiometricDataToAI(bool* pbAuthenticated)
{
    HRESULT hr = S_OK;
    *pbAuthenticated = false;
    
    // Create JSON payload for AI model
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
                *pbAuthenticated = m_aiResponse.isLegitimate;
                
                // Store response for potential use
                m_bAIAuthenticationPassed = m_aiResponse.isLegitimate;
            }
        }
    }
    
    return hr;
}

// Remaining ICredentialProviderCredential methods
STDMETHODIMP CSampleCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (m_pCredProvCredentialEvents)
    {
        m_pCredProvCredentialEvents->Release();
    }
    
    m_pCredProvCredentialEvents = pcpce;
    if (m_pCredProvCredentialEvents)
    {
        m_pCredProvCredentialEvents->AddRef();
    }
    
    return S_OK;
}

STDMETHODIMP CSampleCredential::UnAdvise()
{
    SAFE_RELEASE(m_pCredProvCredentialEvents);
    return S_OK;
}

STDMETHODIMP CSampleCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    
    CAutoLock lock(&m_cs);
    
    m_bSelected = TRUE;
    m_bBiometricCaptureActive = TRUE;
    m_bFirstKeystroke = TRUE;
    
    // Clear previous biometric data
    ResetBiometricData();
    
    // Update status
    UpdateStatusText(L"Ready for authentication");
    
    return S_OK;
}

STDMETHODIMP CSampleCredential::SetDeselected()
{
    CAutoLock lock(&m_cs);
    
    m_bSelected = FALSE;
    m_bBiometricCaptureActive = FALSE;
    
    return S_OK;
}

STDMETHODIMP CSampleCredential::GetFieldState(DWORD dwFieldID, 
                                             CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                             CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    HRESULT hr = S_OK;
    
    if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
    {
        *pcpfs = m_rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = m_rgFieldStatePairs[dwFieldID].cpfis;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
    return hr;
}

STDMETHODIMP CSampleCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    HRESULT hr = S_OK;
    
    if (dwFieldID < FID_NUM_FIELDS && ppwsz)
    {
        hr = SHStrDupW(m_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
    return hr;
}

STDMETHODIMP CSampleCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(phbmp);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    HRESULT hr = S_OK;
    
    if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        *pdwAdjacentTo = FID_PASSWORD;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
    return hr;
}

STDMETHODIMP CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                                            PWSTR* ppwszOptionalStatusText,
                                            CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    
    m_ntsLastResult = ntsStatus;
    return S_OK;
}

STDMETHODIMP CSampleCredential::GetUserSid(PWSTR* ppszSid)
{
    HRESULT hr = S_OK;
    
    if (m_pszUserSid)
    {
        hr = SHStrDupW(m_pszUserSid, ppszSid);
    }
    else
    {
        *ppszSid = nullptr;
    }
    
    return hr;
}

STDMETHODIMP CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                               CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    HRESULT hr = S_OK;
    
    if (dwFieldID < FID_NUM_FIELDS && pcpcfo)
    {
        *pcpcfo = CPCFO_NONE;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
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

// Helper method implementations
HRESULT CSampleCredential::ResetBiometricData()
{
    m_biometricProfile.keystrokes.clear();
    m_biometricProfile.password.clear();
    m_biometricProfile.username.clear();
    m_biometricProfile.totalTypingTime = 0;
    m_biometricProfile.passwordLength = 0;
    
    m_bKeystrokeAnalysisComplete = FALSE;
    m_bAIAuthenticationPassed = FALSE;
    m_bFirstKeystroke = TRUE;
    
    return S_OK;
}

HRESULT CSampleCredential::SecureMemoryCleanup()
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
    
    if (!m_biometricProfile.username.empty())
    {
        SecureZeroMemory(const_cast<PWSTR>(m_biometricProfile.username.c_str()),
                        m_biometricProfile.username.length() * sizeof(WCHAR));
        m_biometricProfile.username.clear();
    }
    
    return S_OK;
}

HRESULT CSampleCredential::LoadConfiguration()
{
    HRESULT hr = S_OK;
    
    // Load AI endpoint
    hr = GetConfigurationValue(CONFIG_AI_ENDPOINT, m_strAIEndpoint);
    if (FAILED(hr))
    {
        m_strAIEndpoint = DEFAULT_AI_ENDPOINT;
    }
    
    // Load API key
    hr = GetConfigurationValue(CONFIG_AI_API_KEY, m_strAPIKey);
    if (FAILED(hr))
    {
        m_strAPIKey = DEFAULT_API_KEY;
    }
    
    // Load timeout
    DWORD dwTimeout = 0;
    hr = GetConfigurationDWORD(CONFIG_TIMEOUT, dwTimeout);
    if (SUCCEEDED(hr))
    {
        m_dwTimeout = dwTimeout;
    }
    
    // Load debug mode
    DWORD dwDebugMode = 0;
    hr = GetConfigurationDWORD(CONFIG_DEBUG_MODE, dwDebugMode);
    if (SUCCEEDED(hr))
    {
        m_bDebugMode = (dwDebugMode != 0);
    }
    
    return S_OK;
}

HRESULT CSampleCredential::UpdateStatusText(PCWSTR pszStatus)
{
    HRESULT hr = S_OK;
    
    if (m_pCredProvCredentialEvents)
    {
        hr = m_pCredProvCredentialEvents->SetFieldString(this, FID_BIOMETRIC_STATUS, pszStatus);
    }
    
    return hr;
}
