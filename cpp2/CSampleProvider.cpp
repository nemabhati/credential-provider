#include "CSampleProvider.h"
#include "guid.h"
#include "Dll.h"
#include <shlwapi.h>

// Provider implementation
CSampleProvider::CSampleProvider() :
    m_cRef(1),
    m_pCredential(nullptr),
    m_cpus(CPUS_INVALID),
    m_dwFlags(0),
    m_pCredProvEvents(nullptr),
    m_upAdviseContext(0)
{
    DllAddRef();
}

CSampleProvider::~CSampleProvider()
{
    SAFE_RELEASE(m_pCredential);
    SAFE_RELEASE(m_pCredProvEvents);
    DllRelease();
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
    else
    {
        return E_NOINTERFACE;
    }
    
    AddRef();
    return S_OK;
}

STDMETHODIMP CSampleProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
    HRESULT hr = S_OK;
    
    m_cpus = cpus;
    m_dwFlags = dwFlags;
    
    // Create credential based on usage scenario
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // Create the credential
        m_pCredential = new CSampleCredential();
        if (m_pCredential)
        {
            hr = m_pCredential->Initialize(cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
        break;
        
    case CPUS_CREDUI:
        // Not supported in this implementation
        hr = E_NOTIMPL;
        break;
        
    default:
        hr = E_INVALIDARG;
        break;
    }
    
    return hr;
}

STDMETHODIMP CSampleProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    UNREFERENCED_PARAMETER(pcpcs);
    return E_NOTIMPL;
}

STDMETHODIMP CSampleProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
    if (m_pCredProvEvents)
    {
        m_pCredProvEvents->Release();
    }
    
    m_pCredProvEvents = pcpe;
    if (m_pCredProvEvents)
    {
        m_pCredProvEvents->AddRef();
    }
    
    m_upAdviseContext = upAdviseContext;
    
    return S_OK;
}

STDMETHODIMP CSampleProvider::UnAdvise()
{
    SAFE_RELEASE(m_pCredProvEvents);
    m_upAdviseContext = 0;
    return S_OK;
}

STDMETHODIMP CSampleProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    if (pdwCount)
    {
        *pdwCount = FID_NUM_FIELDS;
        return S_OK;
    }
    
    return E_INVALIDARG;
}

STDMETHODIMP CSampleProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr = S_OK;
    
    if (dwIndex < FID_NUM_FIELDS && ppcpfd)
    {
        *ppcpfd = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        
        if (*ppcpfd)
        {
            (*ppcpfd)->dwFieldID = s_rgCredProvFieldDescriptors[dwIndex].dwFieldID;
            (*ppcpfd)->cpft = s_rgCredProvFieldDescriptors[dwIndex].cpft;
            (*ppcpfd)->cpfg = s_rgCredProvFieldDescriptors[dwIndex].cpfg;
            
            hr = SHStrDupW(s_rgCredProvFieldDescriptors[dwIndex].pszLabel, &(*ppcpfd)->pszLabel);
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
    return hr;
}

STDMETHODIMP CSampleProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    if (pdwCount && pdwDefault && pbAutoLogonWithDefault)
    {
        *pdwCount = (m_pCredential) ? 1 : 0;
        *pdwDefault = 0;
        *pbAutoLogonWithDefault = FALSE;
        return S_OK;
    }
    
    return E_INVALIDARG;
}

STDMETHODIMP CSampleProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    HRESULT hr = S_OK;
    
    if (dwIndex == 0 && ppcpc && m_pCredential)
    {
        hr = m_pCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
    return hr;
}

HRESULT CSampleProvider::CreateInstance(REFIID riid, void** ppv)
{
    HRESULT hr = S_OK;
    
    CSampleProvider* pProvider = new CSampleProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}

// Class factory implementation
CSampleProviderFactory::CSampleProviderFactory() : m_cRef(1)
{
    DllAddRef();
}

CSampleProviderFactory::~CSampleProviderFactory()
{
    DllRelease();
}

STDMETHODIMP_(ULONG) CSampleProviderFactory::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CSampleProviderFactory::Release()
{
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return cRef;
}

STDMETHODIMP CSampleProviderFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (ppv == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *ppv = nullptr;
    
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
    {
        *ppv = static_cast<IClassFactory*>(this);
    }
    else
    {
        return E_NOINTERFACE;
    }
    
    AddRef();
    return S_OK;
}

STDMETHODIMP CSampleProviderFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    HRESULT hr = S_OK;
    
    if (pUnkOuter)
    {
        hr = CLASS_E_NOAGGREGATION;
    }
    else
    {
        hr = CSampleProvider::CreateInstance(riid, ppv);
    }
    
    return hr;
}

STDMETHODIMP CSampleProviderFactory::LockServer(BOOL fLock)
{
    if (fLock)
    {
        DllAddRef();
    }
    else
    {
        DllRelease();
    }
    
    return S_OK;
}

HRESULT CSampleProviderFactory_CreateInstance(REFIID riid, void** ppv)
{
    HRESULT hr = S_OK;
    
    CSampleProviderFactory* pFactory = new CSampleProviderFactory();
    if (pFactory)
    {
        hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}
