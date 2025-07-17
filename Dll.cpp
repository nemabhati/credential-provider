#include "Dll.h"
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"
#include "helpers.h"
#include <strsafe.h>

// Global variables
HINSTANCE g_hInst = NULL;
LONG g_cRef = 0;

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hInst = hModule;
        DisableThreadLibraryCalls(hModule);
        InitializeCredentialProvider();
        break;
        
    case DLL_PROCESS_DETACH:
        CleanupCredentialProvider();
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    
    return TRUE;
}

// COM server entry points
STDAPI DllCanUnloadNow(void)
{
    return (g_cRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    HRESULT hr = E_FAIL;
    
    if (ppv == NULL)
    {
        return E_INVALIDARG;
    }
    
    *ppv = NULL;
    
    if (IsEqualCLSID(rclsid, CLSID_CSampleProvider))
    {
        CSampleFactory* pFactory = new CSampleFactory();
        if (pFactory)
        {
            hr = pFactory->QueryInterface(riid, ppv);
            pFactory->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    
    return hr;
}

STDAPI DllRegisterServer(void)
{
    HRESULT hr = RegisterCredentialProvider();
    if (SUCCEEDED(hr))
    {
        hr = LoadConfiguration();
    }
    return hr;
}

STDAPI DllUnregisterServer(void)
{
    return UnregisterCredentialProvider();
}

// Reference counting
void DllAddRef(void)
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease(void)
{
    InterlockedDecrement(&g_cRef);
}

// CSampleFactory implementation
CSampleFactory::CSampleFactory() : m_cRef(1)
{
    DllAddRef();
}

CSampleFactory::~CSampleFactory()
{
    DllRelease();
}

STDMETHODIMP CSampleFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (ppv == NULL)
    {
        return E_INVALIDARG;
    }
    
    *ppv = NULL;
    
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
    {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    
    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CSampleFactory::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CSampleFactory::Release()
{
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return cRef;
}

STDMETHODIMP CSampleFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    HRESULT hr = E_FAIL;
    
    if (ppv == NULL)
    {
        return E_INVALIDARG;
    }
    
    *ppv = NULL;
    
    if (pUnkOuter != NULL)
    {
        return CLASS_E_NOAGGREGATION;
    }
    
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

STDMETHODIMP CSampleFactory::LockServer(BOOL fLock)
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

// Registry helper functions
HRESULT RegisterCredentialProvider()
{
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    HKEY hSubKey = NULL;
    
    // Register COM class
    hr = CreateRegistryKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", &hKey);
    if (SUCCEEDED(hr))
    {
        hr = CreateRegistryKey(hKey, CLSID_CSampleProvider_STRING, &hSubKey);
        if (SUCCEEDED(hr))
        {
            hr = SetRegistryKeyValue(hSubKey, NULL, CREDENTIAL_PROVIDER_FRIENDLY_NAME);
            if (SUCCEEDED(hr))
            {
                HKEY hInprocKey = NULL;
                hr = CreateRegistryKey(hSubKey, L"InprocServer32", &hInprocKey);
                if (SUCCEEDED(hr))
                {
                    // Get module path
                    WCHAR szModulePath[MAX_PATH];
                    if (GetModuleFileName(g_hInst, szModulePath, ARRAYSIZE(szModulePath)))
                    {
                        hr = SetRegistryKeyValue(hInprocKey, NULL, szModulePath);
                        if (SUCCEEDED(hr))
                        {
                            hr = SetRegistryKeyValue(hInprocKey, L"ThreadingModel", CREDENTIAL_PROVIDER_THREADING_MODEL);
                        }
                    }
                    else
                    {
                        hr = GetLastErrorAsHRESULT();
                    }
                    RegCloseKey(hInprocKey);
                }
            }
            RegCloseKey(hSubKey);
        }
        RegCloseKey(hKey);
    }
    
    // Register credential provider
    if (SUCCEEDED(hr))
    {
        hr = CreateRegistryKey(HKEY_LOCAL_MACHINE, CREDENTIAL_PROVIDER_REGISTRY_KEY, &hKey);
        if (SUCCEEDED(hr))
        {
            hr = CreateRegistryKey(hKey, CLSID_CSampleProvider_STRING, &hSubKey);
            if (SUCCEEDED(hr))
            {
                hr = SetRegistryKeyValue(hSubKey, NULL, CREDENTIAL_PROVIDER_FRIENDLY_NAME);
                RegCloseKey(hSubKey);
            }
            RegCloseKey(hKey);
        }
    }
    
    return hr;
}

HRESULT UnregisterCredentialProvider()
{
    HRESULT hr = S_OK;
    
    // Unregister credential provider
    DeleteRegistryKey(HKEY_LOCAL_MACHINE, CREDENTIAL_PROVIDER_REGISTRY_KEY L"\\" CLSID_CSampleProvider_STRING);
    
    // Unregister COM class
    DeleteRegistryKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\" CLSID_CSampleProvider_STRING);
    
    return hr;
}

HRESULT CreateRegistryKey(HKEY hKeyParent, LPCWSTR pszKeyName, PHKEY phKey)
{
    LONG result = RegCreateKeyExW(hKeyParent, pszKeyName, 0, NULL, 0, KEY_WRITE, NULL, phKey, NULL);
    return HRESULT_FROM_WIN32(result);
}

HRESULT SetRegistryKeyValue(HKEY hKey, LPCWSTR pszValueName, LPCWSTR pszValue)
{
    LONG result = RegSetValueExW(hKey, pszValueName, 0, REG_SZ, (CONST BYTE*)pszValue, (wcslen(pszValue) + 1) * sizeof(WCHAR));
    return HRESULT_FROM_WIN32(result);
}

HRESULT DeleteRegistryKey(HKEY hKeyParent, LPCWSTR pszKeyName)
{
    LONG result = RegDeleteKeyW(hKeyParent, pszKeyName);
    return HRESULT_FROM_WIN32(result);
}

// Configuration helper functions
HRESULT LoadConfiguration()
{
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, BIOMETRIC_CONFIG_REGISTRY_KEY, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS)
    {
        // Configuration already exists
        RegCloseKey(hKey);
        return S_OK;
    }
    
    // Create default configuration
    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, BIOMETRIC_CONFIG_REGISTRY_KEY, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS)
    {
        SetRegistryKeyValue(hKey, CONFIG_AI_ENDPOINT, DEFAULT_AI_ENDPOINT);
        SetRegistryKeyValue(hKey, CONFIG_AI_API_KEY, DEFAULT_API_KEY);
        SetRegistryKeyValue(hKey, CONFIG_TIMEOUT, DEFAULT_TIMEOUT);
        SetRegistryKeyValue(hKey, CONFIG_ENABLED, DEFAULT_ENABLED);
        SetRegistryKeyValue(hKey, CONFIG_DEBUG_MODE, DEFAULT_DEBUG_MODE);
        
        RegCloseKey(hKey);
    }
    else
    {
        hr = HRESULT_FROM_WIN32(result);
    }
    
    return hr;
}

HRESULT SaveConfiguration()
{
    // Configuration is saved when set
    return S_OK;
}

HRESULT GetConfigurationValue(LPCWSTR pszValueName, std::wstring& value)
{
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, BIOMETRIC_CONFIG_REGISTRY_KEY, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS)
    {
        hr = ReadRegistryString(hKey, pszValueName, value);
        RegCloseKey(hKey);
    }
    else
    {
        hr = HRESULT_FROM_WIN32(result);
    }
    
    return hr;
}

HRESULT SetConfigurationValue(LPCWSTR pszValueName, LPCWSTR pszValue)
{
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, BIOMETRIC_CONFIG_REGISTRY_KEY, 0, KEY_WRITE, &hKey);
    if (result == ERROR_SUCCESS)
    {
        hr = WriteRegistryString(hKey, pszValueName, pszValue);
        RegCloseKey(hKey);
    }
    else
    {
        hr = HRESULT_FROM_WIN32(result);
    }
    
    return hr;
}

// Initialization functions
HRESULT InitializeCredentialProvider()
{
    HRESULT hr = S_OK;
    
    // Initialize performance timer
    hr = InitializePerformanceTimer();
    if (SUCCEEDED(hr))
    {
        // Initialize WinHTTP
        hr = InitializeWinHTTP();
    }
    
    return hr;
}

HRESULT CleanupCredentialProvider()
{
    HRESULT hr = S_OK;
    
    // Cleanup WinHTTP
    hr = CleanupWinHTTP();
    
    return hr;
}