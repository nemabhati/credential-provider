#pragma once

// {A52B7C3D-4F2E-4A7B-9F1E-3D6C8A5B4E9F}
DEFINE_GUID(CLSID_CSampleProvider, 
    0xa52b7c3d, 0x4f2e, 0x4a7b, 0x9f, 0x1e, 0x3d, 0x6c, 0x8a, 0x5b, 0x4e, 0x9f);

// {B63C8D4E-5F3F-4B8C-AF2F-4E7D9B6C5FAF}
DEFINE_GUID(CLSID_CSampleCredential, 
    0xb63c8d4e, 0x5f3f, 0x4b8c, 0xaf, 0x2f, 0x4e, 0x7d, 0x9b, 0x6c, 0x5f, 0xaf);

// {C74D9E5F-6G4G-5C9D-BG3G-5F8E-AC7D6GBG}
DEFINE_GUID(CLSID_CSampleFactory, 
    0xc74d9e5f, 0x6040, 0x5c9d, 0xb030, 0x5f, 0x8e, 0xac, 0x7d, 0x60, 0xb0);

// Provider name and description
#define PROVIDER_NAME L"Sample Biometric Credential Provider"
#define PROVIDER_DESCRIPTION L"Behavioral biometric authentication using keystroke dynamics"

// Registry keys for credential provider registration
#define CREDENTIAL_PROVIDER_REGISTRY_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers"
#define CREDENTIAL_PROVIDER_FILTER_REGISTRY_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters"

// Configuration registry key
#define BIOMETRIC_CONFIG_REGISTRY_KEY L"SOFTWARE\\BiometricCredentialProvider"

// Version information
#define PROVIDER_VERSION_MAJOR 1
#define PROVIDER_VERSION_MINOR 0
#define PROVIDER_VERSION_BUILD 0
#define PROVIDER_VERSION_REVISION 1

// String representations of GUIDs (for registry)
#define CLSID_CSampleProvider_STRING L"{A52B7C3D-4F2E-4A7B-9F1E-3D6C8A5B4E9F}"
#define CLSID_CSampleCredential_STRING L"{B63C8D4E-5F3F-4B8C-AF2F-4E7D9B6C5FAF}"
#define CLSID_CSampleFactory_STRING L"{C74D9E5F-6040-5C9D-B030-5F8EAC7D60B0}"

// External declarations
extern "C" {
    extern const CLSID CLSID_CSampleProvider;
    extern const CLSID CLSID_CSampleCredential;
    extern const CLSID CLSID_CSampleFactory;
}