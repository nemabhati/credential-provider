#include "Dll.h"
#include "CSampleProvider.h"
#include "guid.h"
#include <strsafe.h>

// Global variables
HINSTANCE g_hInst = nullptr;
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
        break;
        
    case DLL_PROCESS_DETACH:
        break;
    }
    
    return TRUE;
}

// Reference counting
void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

// Standard COM exports
STDAPI DllCanUnloadNow()
{
    return (g_cRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    HRESULT hr = S_OK;
    
    if (IsEqualCLSID(rclsid, CLSID_CSample))
    {
        hr = CSampleProviderFactory_CreateInstance(riid, ppv);
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    
    return hr;
}

STDAPI DllRegisterServer()
{
    HRESULT hr = S_OK;
    
    // Register the credential provider
    WCHAR szCLSID[MAX_PATH];
    StringFromGUID2(CLSID_CSample, szCLSID, ARRAYSIZE(szCLSID));
    
    WCHAR szSubkey[MAX_PATH];
    
    // Register COM server
    hr = StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    if (SUCCEEDED(hr))
    {
        hr = SetConfigurationValue(szSubkey, L"Biometric Credential Provider");
        
        if (SUCCEEDED(hr))
        {
            hr = StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s\\InprocServer32", szCLSID);
            if (SUCCEEDED(hr))
            {
                WCHAR szModule[MAX_PATH];
                GetModuleFileNameW(g_hInst, szModule, ARRAYSIZE(szModule));
                
                hr = SetConfigurationValue(szSubkey, szModule);
                
                if (SUCCEEDED(hr))
                {
                    hr = SetConfigurationValue(L"ThreadingModel", L"Apartment");
                }
            }
        }
    }
    
    // Register credential provider
    if (SUCCEEDED(hr))
    {
        hr = StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), 
                             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", 
                             szCLSID);
        if (SUCCEEDED(hr))
        {
            hr = SetConfigurationValue(szSubkey, L"Biometric Credential Provider");
        }
    }
    
    return hr;
}

STDAPI DllUnregisterServer()
{
    HRESULT hr = S_OK;
    
    WCHAR szCLSID[MAX_PATH];
    StringFromGUID2(CLSID_CSample, szCLSID, ARRAYSIZE(szCLSID));
    
    WCHAR szSubkey[MAX_PATH];
    
    // Unregister credential provider
    hr = StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), 
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", 
                         szCLSID);
    if (SUCCEEDED(hr))
    {
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, szSubkey);
    }
    
    // Unregister COM server
    hr = StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    if (SUCCEEDED(hr))
    {
        RegDeleteTreeW(HKEY_CLASSES_ROOT, szSubkey);
    }
    
    return hr;
}
