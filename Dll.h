#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include "common.h"

// DLL entry points
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// COM server entry points
STDAPI DllCanUnloadNow(void);
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv);
STDAPI DllRegisterServer(void);
STDAPI DllUnregisterServer(void);

// Reference counting
void DllAddRef(void);
void DllRelease(void);

// Global variables
extern HINSTANCE g_hInst;
extern LONG g_cRef;

// Class factory
class CSampleFactory : public IClassFactory
{
public:
    CSampleFactory();
    virtual ~CSampleFactory();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();

    // IClassFactory
    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv);
    STDMETHODIMP LockServer(BOOL fLock);

private:
    LONG m_cRef;
};

// Registry helper functions
HRESULT RegisterCredentialProvider();
HRESULT UnregisterCredentialProvider();
HRESULT CreateRegistryKey(HKEY hKeyParent, LPCWSTR pszKeyName, PHKEY phKey);
HRESULT SetRegistryKeyValue(HKEY hKey, LPCWSTR pszValueName, LPCWSTR pszValue);
HRESULT DeleteRegistryKey(HKEY hKeyParent, LPCWSTR pszKeyName);

// Configuration helper functions
HRESULT LoadConfiguration();
HRESULT SaveConfiguration();
HRESULT GetConfigurationValue(LPCWSTR pszValueName, std::wstring& value);
HRESULT SetConfigurationValue(LPCWSTR pszValueName, LPCWSTR pszValue);

// Initialization functions
HRESULT InitializeCredentialProvider();
HRESULT CleanupCredentialProvider();

// Constants for registry configuration
#define CREDENTIAL_PROVIDER_DLL_NAME L"SampleV2CredentialProvider.dll"
#define CREDENTIAL_PROVIDER_FRIENDLY_NAME L"Sample Biometric Credential Provider"
#define CREDENTIAL_PROVIDER_THREADING_MODEL L"Both"

// Configuration value names
#define CONFIG_AI_ENDPOINT L"AIEndpoint"
#define CONFIG_AI_API_KEY L"APIKey"
#define CONFIG_TIMEOUT L"Timeout"
#define CONFIG_ENABLED L"Enabled"
#define CONFIG_DEBUG_MODE L"DebugMode"

// Default configuration values
#define DEFAULT_AI_ENDPOINT L"https://your-ai-model.com/api/authenticate"
#define DEFAULT_API_KEY L"your-api-key-here"
#define DEFAULT_TIMEOUT L"30000"
#define DEFAULT_ENABLED L"1"
#define DEFAULT_DEBUG_MODE L"0"