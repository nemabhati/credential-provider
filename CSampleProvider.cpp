#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"
#include "helpers.h"
#include "Dll.h"
#include <strsafe.h>

CSampleProvider::CSampleProvider() :
    m_cRef(1),
    m_cpus(CPUS_INVALID),
    m_dwFlags(0),
    m_pCredProviderEvents(nullptr),
    m_upAdviseContext(0),
    m_pUserArray(nullptr),
    m_pCredentials(nullptr),
    m_dwCredentialCount(0),
    m_dwDefaultCredential(0),
    m_pCredentialSerialization(nullptr),
    m_bEnabled(TRUE),
    m_dwTimeout(30000),
    m_bDebugMode(FALSE),
    m_bCriticalSectionInitialized(FALSE)
{
    DllAddRef();
    
    // Initialize critical section
    InitializeCriticalSection(&m_cs);
    m_bCriticalSectionInitialized = TRUE;
    
    // Load configuration
    _LoadUserConfiguration();
}

CSampleProvider::~CSampleProvider()
{
    _CleanupCredentials();
    
    if (m_pCredProviderEvents)
    {
        m_pCredProviderEvents->Release();
        m_pCredProviderEvents = nullptr;
    }
    
    if (m_pUserArray)
    {
        m_pUserArray->Release();
        m_pUserArray = nullptr;
    }
    
    if (m_pCredentialSerialization)
    {
        if (m_pCredentialSerialization->rgbSerialization)
        {
            CoTaskMemFree(m_pCredentialSerialization->rgbSerialization);
        }
        CoTaskMemFree(m_pCredentialSerialization);
    }
    
    if (m_bCriticalSectionInitialized)
    {
        DeleteCriticalSection(&m_cs);
    }
    
    DllRelease();
}

// IUnknown implementation
STDMETHODIMP CSampleProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (ppv == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppv = nullptr;
    
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_ICredentialProvider))
    {
        *ppv = static_cast<ICredentialProvider*>(this);
    }
    else if (IsEqualIID(riid, IID_ICredentialProviderSetUserArray))
    {
        *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    }
    else
    {
        return E_NOINTERFACE;
    }
    
    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) CSampleProvider::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CSampleProvider::Release()
{
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return cRef;
}

// ICredentialProvider implementation
STDMETHODIMP CSampleProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
    CAutoLock lock(&m_cs);
    
    m_cpus = cpus;
    m_dwFlags = dwFlags;
    
    // Only support logon and unlock scenarios
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
    {
        return _EnumerateCredentials();
    }
    
    return E_NOTIMPL;
}

STDMETHODIMP CSampleProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    CAutoLock lock(&m_cs);
    
    if (pcpcs)
    {
        // Store serialization for later use
        m_pCredentialSerialization = (CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION));
        if (m_pCredentialSerialization)
        {
            *m_pCredentialSerialization = *pcpcs;
            
            if (pcpcs->rgbSerialization && pcpcs->cbSerialization > 0)
            {
                m_pCredentialSerialization->rgbSerialization = (BYTE*)CoTaskMemAlloc(pcpcs->cbSerialization);
                if (m_pCredentialSerialization->rgbSerialization)
                {
                    CopyMemory(m_pCredentialSerialization->rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
                }
            }
        }
    }
    
    return S_OK;
}

STDMETHODIMP CSampleProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
    CAutoLock lock(&m_cs);
    
    if (m_pCredProviderEvents)
    {
        m_pCredProviderEvents->Release();
    }
    
    m_pCredProviderEvents = pcpe;
    if (m_pCredProviderEvents)
    {
        m_pCredProviderEvents->AddRef();
    }
    
    m_upAdviseContext = upAdviseContext;
    
    return S_OK;
}

STDMETHODIMP CSampleProvider::UnAdvise()
{
    CAutoLock lock(&m_cs);
    
    if (m_pCredProviderEvents)
    {
        m_pCredProviderEvents->Release();
        m_pCredProviderEvents = nullptr;
    }
    
    m_upAdviseContext = 0;
    
    return S_OK;
}

STDMETHODIMP CSampleProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    if (pdwCount == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *pdwCount = FID_NUM_FIELDS;
    return S_OK;
}

STDMETHODIMP CSampleProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (ppcpfd == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppcpfd = nullptr;
    
    if (dwIndex >= FID_NUM_FIELDS)
    {
        return E_INVALIDARG;
    }
    
    return CloneFieldDescriptor(&s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
}

STDMETHODIMP CSampleProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    if (pdwCount == nullptr || pdwDefault == nullptr || pbAutoLogonWithDefault == nullptr)
    {
        return E_INVALIDARG;
    }
    
    CAutoLock lock(&m_cs);
    
    *pdwCount = m_dwCredentialCount;
    *pdwDefault = m_dwDefaultCredential;
    *pbAutoLogonWithDefault = FALSE;
    
    return S_OK;
}

STDMETHODIMP CSampleProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (ppcpc == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppcpc = nullptr;
    
    CAutoLock lock(&m_cs);
    
    if (dwIndex >= m_dwCredentialCount || m_pCredentials == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppcpc = m_pCredentials[dwIndex];
    (*ppcpc)->AddRef();
    
    return S_OK;
}

// ICredentialProviderSetUserArray implementation
STDMETHODIMP CSampleProvider::SetUserArray(ICredentialProviderUserArray* users)
{
    CAutoLock lock(&m_cs);
    
    if (m_pUserArray)
    {
        m_pUserArray->Release();
    }
    
    m_pUserArray = users;
    if (m_pUserArray)
    {
        m_pUserArray->AddRef();
    }
    
    return S_OK;
}

// Private methods
HRESULT CSampleProvider::_CreateCredential(ICredentialProviderUser* pUser, CSampleCredential** ppCredential)
{
    if (ppCredential == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppCredential = nullptr;
    
    CSampleCredential* pCredential = new CSampleCredential();
    if (pCredential)
    {
        HRESULT hr = pCredential->Initialize(m_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pUser);
        if (SUCCEEDED(hr))
        {
            *ppCredential = pCredential;
        }
        else
        {
            pCredential->Release();
        }
        return hr;
    }
    
    return E_OUTOFMEMORY;
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
    _CleanupCredentials();
    
    // Check if provider is enabled
    BOOL bEnabled = FALSE;
    _IsCredentialProviderEnabled(&bEnabled);
    if (!bEnabled)
    {
        return S_OK;
    }
    
    HRESULT hr = S_OK;
    
    if (m_pUserArray)
    {
        // Enumerate users from user array
        DWORD dwUserCount = 0;
        hr = m_pUserArray->GetCount(&dwUserCount);
        if (SUCCEEDED(hr))
        {
            m_pCredentials = new CSampleCredential*[dwUserCount];
            if (m_pCredentials)
            {
                ZeroMemory(m_pCredentials, sizeof(CSampleCredential*) * dwUserCount);
                
                for (DWORD i = 0; i < dwUserCount && SUCCEEDED(hr); i++)
                {
                    ICredentialProviderUser* pUser = nullptr;
                    hr = m_pUserArray->GetAt(i, &pUser);
                    if (SUCCEEDED(hr))
                    {
                        hr = _CreateCredential(pUser, &m_pCredentials[m_dwCredentialCount]);
                        if (SUCCEEDED(hr))
                        {
                            m_dwCredentialCount++;
                        }
                        pUser->Release();
                    }
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }
    else
    {
        // Create a generic credential when no user array is available
        m_pCredentials = new CSampleCredential*[1];
        if (m_pCredentials)
        {
            ZeroMemory(m_pCredentials, sizeof(CSampleCredential*));
            
            hr = _CreateCredential(nullptr, &m_pCredentials[0]);
            if (SUCCEEDED(hr))
            {
                m_dwCredentialCount = 1;
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    
    return hr;
}

void CSampleProvider::_CleanupCredentials()
{
    if (m_pCredentials)
    {
        for (DWORD i = 0; i < m_dwCredentialCount; i++)
        {
            if (m_pCredentials[i])
            {
                m_pCredentials[i]->Release();
                m_pCredentials[i] = nullptr;
            }
        }
        delete[] m_pCredentials;
        m_pCredentials = nullptr;
    }
    
    m_dwCredentialCount = 0;
    m_dwDefaultCredential = 0;
}

HRESULT CSampleProvider::_GetSerializedCredentials(PWSTR* ppwszUsername, PWSTR* ppwszPassword, PWSTR* ppwszDomain)
{
    if (ppwszUsername == nullptr || ppwszPassword == nullptr || ppwszDomain == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppwszUsername = nullptr;
    *ppwszPassword = nullptr;
    *ppwszDomain = nullptr;
    
    if (m_pCredentialSerialization)
    {
        // Extract credentials from serialization
        KERB_INTERACTIVE_UNLOCK_LOGON* pUnlockLogon = (KERB_INTERACTIVE_UNLOCK_LOGON*)m_pCredentialSerialization->rgbSerialization;
        if (pUnlockLogon)
        {
            // Extract username
            if (pUnlockLogon->Logon.UserName.Buffer && pUnlockLogon->Logon.UserName.Length > 0)
            {
                HRESULT hr = SHStrDupW(pUnlockLogon->Logon.UserName.Buffer, ppwszUsername);
                if (FAILED(hr))
                {
                    return hr;
                }
            }
            
            // Extract password
            if (pUnlockLogon->Logon.Password.Buffer && pUnlockLogon->Logon.Password.Length > 0)
            {
                HRESULT hr = SHStrDupW(pUnlockLogon->Logon.Password.Buffer, ppwszPassword);
                if (FAILED(hr))
                {
                    CoTaskMemFree(*ppwszUsername);
                    *ppwszUsername = nullptr;
                    return hr;
                }
            }
            
            // Extract domain
            if (pUnlockLogon->Logon.LogonDomainName.Buffer && pUnlockLogon->Logon.LogonDomainName.Length > 0)
            {
                HRESULT hr = SHStrDupW(pUnlockLogon->Logon.LogonDomainName.Buffer, ppwszDomain);
                if (FAILED(hr))
                {
                    CoTaskMemFree(*ppwszUsername);
                    CoTaskMemFree(*ppwszPassword);
                    *ppwszUsername = nullptr;
                    *ppwszPassword = nullptr;
                    return hr;
                }
            }
        }
    }
    
    return S_OK;
}

HRESULT CSampleProvider::_IsCredentialProviderEnabled(BOOL* pbEnabled)
{
    if (pbEnabled == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *pbEnabled = m_bEnabled;
    return S_OK;
}

HRESULT CSampleProvider::_LoadUserConfiguration()
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
    std::wstring strTimeout;
    hr = GetConfigurationValue(CONFIG_TIMEOUT, strTimeout);
    if (SUCCEEDED(hr))
    {
        m_dwTimeout = _wtoi(strTimeout.c_str());
    }
    else
    {
        m_dwTimeout = _wtoi(DEFAULT_TIMEOUT);
    }
    
    // Load enabled flag
    std::wstring strEnabled;
    hr = GetConfigurationValue(CONFIG_ENABLED, strEnabled);
    if (SUCCEEDED(hr))
    {
        m_bEnabled = (_wtoi(strEnabled.c_str()) != 0);
    }
    else
    {
        m_bEnabled = (_wtoi(DEFAULT_ENABLED) != 0);
    }
    
    // Load debug mode
    std::wstring strDebugMode;
    hr = GetConfigurationValue(CONFIG_DEBUG_MODE, strDebugMode);
    if (SUCCEEDED(hr))
    {
        m_bDebugMode = (_wtoi(strDebugMode.c_str()) != 0);
    }
    else
    {
        m_bDebugMode = (_wtoi(DEFAULT_DEBUG_MODE) != 0);
    }
    
    return S_OK;
}

// Helper functions
HRESULT CSampleProvider_CreateInstance(REFIID riid, void** ppv)
{
    if (ppv == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppv = nullptr;
    
    CSampleProvider* pProvider = new CSampleProvider();
    if (pProvider)
    {
        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }
    
    return E_OUTOFMEMORY;
}

HRESULT CreateFieldDescriptor(CREDENTIAL_PROVIDER_FIELD_TYPE cpft, LPCWSTR pszLabel, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppFieldDescriptor)
{
    if (ppFieldDescriptor == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppFieldDescriptor = nullptr;
    
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pFieldDescriptor = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (pFieldDescriptor)
    {
        pFieldDescriptor->dwFieldID = 0;
        pFieldDescriptor->cpft = cpft;
        pFieldDescriptor->pszLabel = nullptr;
        pFieldDescriptor->guidFieldType = CPFG_CREDENTIAL_PROVIDER_LABEL;
        
        if (pszLabel)
        {
            HRESULT hr = SHStrDupW(pszLabel, &pFieldDescriptor->pszLabel);
            if (FAILED(hr))
            {
                CoTaskMemFree(pFieldDescriptor);
                return hr;
            }
        }
        
        *ppFieldDescriptor = pFieldDescriptor;
        return S_OK;
    }
    
    return E_OUTOFMEMORY;
}

HRESULT CloneFieldDescriptor(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppFieldDescriptor)
{
    if (pcpfd == nullptr || ppFieldDescriptor == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppFieldDescriptor = nullptr;
    
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pFieldDescriptor = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (pFieldDescriptor)
    {
        *pFieldDescriptor = *pcpfd;
        pFieldDescriptor->pszLabel = nullptr;
        
        if (pcpfd->pszLabel)
        {
            HRESULT hr = SHStrDupW(pcpfd->pszLabel, &pFieldDescriptor->pszLabel);
            if (FAILED(hr))
            {
                CoTaskMemFree(pFieldDescriptor);
                return hr;
            }
        }
        
        *ppFieldDescriptor = pFieldDescriptor;
        return S_OK;
    }
    
    return E_OUTOFMEMORY;
}

void FreeFieldDescriptor(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd)
{
    if (pcpfd)
    {
        CoTaskMemFree(pcpfd->pszLabel);
        CoTaskMemFree(pcpfd);
    }
}