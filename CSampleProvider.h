#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <unknwn.h>
#include "common.h"

class CSampleCredential;

class CSampleProvider : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
    CSampleProvider();
    virtual ~CSampleProvider();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();

    // ICredentialProvider
    STDMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    STDMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    STDMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    STDMETHODIMP UnAdvise();
    STDMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    STDMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    STDMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    STDMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

    // ICredentialProviderSetUserArray
    STDMETHODIMP SetUserArray(ICredentialProviderUserArray* users);

private:
    HRESULT _CreateCredential(ICredentialProviderUser* pUser, CSampleCredential** ppCredential);
    HRESULT _EnumerateCredentials();
    void _CleanupCredentials();
    HRESULT _GetSerializedCredentials(PWSTR* ppwszUsername, PWSTR* ppwszPassword, PWSTR* ppwszDomain);
    HRESULT _IsCredentialProviderEnabled(BOOL* pbEnabled);
    HRESULT _LoadUserConfiguration();

private:
    LONG m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    DWORD m_dwFlags;
    
    // Event handling
    ICredentialProviderEvents* m_pCredProviderEvents;
    UINT_PTR m_upAdviseContext;
    
    // User array
    ICredentialProviderUserArray* m_pUserArray;
    
    // Credentials
    CSampleCredential** m_pCredentials;
    DWORD m_dwCredentialCount;
    DWORD m_dwDefaultCredential;
    
    // Serialization
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* m_pCredentialSerialization;
    
    // Configuration
    BOOL m_bEnabled;
    std::wstring m_strAIEndpoint;
    std::wstring m_strAPIKey;
    DWORD m_dwTimeout;
    BOOL m_bDebugMode;
    
    // Thread safety
    CRITICAL_SECTION m_cs;
    BOOL m_bCriticalSectionInitialized;
};

// Helper functions for credential provider
HRESULT CSampleProvider_CreateInstance(REFIID riid, void** ppv);
HRESULT CreateFieldDescriptor(CREDENTIAL_PROVIDER_FIELD_TYPE cpft, LPCWSTR pszLabel, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppFieldDescriptor);
HRESULT CloneFieldDescriptor(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppFieldDescriptor);
void FreeFieldDescriptor(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd);

// Constants
#define MAX_CREDENTIALS 10
#define MAX_USERS 100