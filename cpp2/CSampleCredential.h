#pragma once

#include "common.h"
#include "helpers.h"
#include <credentialprovider.h>

class CSampleCredential : public ICredentialProviderCredential2
{
public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)();
    STDMETHOD_(ULONG, Release)();
    STDMETHOD(QueryInterface)(REFIID riid, void** ppv);

    // ICredentialProviderCredential
    STDMETHOD(Advise)(ICredentialProviderCredentialEvents* pcpce);
    STDMETHOD(UnAdvise)();
    STDMETHOD(SetSelected)(BOOL* pbAutoLogon);
    STDMETHOD(SetDeselected)();
    STDMETHOD(GetFieldState)(DWORD dwFieldID, 
                            CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    STDMETHOD(GetStringValue)(DWORD dwFieldID, PWSTR* ppwsz);
    STDMETHOD(GetBitmapValue)(DWORD dwFieldID, HBITMAP* phbmp);
    STDMETHOD(GetCheckboxValue)(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    STDMETHOD(GetSubmitButtonValue)(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    STDMETHOD(GetComboBoxValueCount)(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    STDMETHOD(GetComboBoxValueAt)(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    STDMETHOD(SetStringValue)(DWORD dwFieldID, PCWSTR pwz);
    STDMETHOD(SetCheckboxValue)(DWORD dwFieldID, BOOL bChecked);
    STDMETHOD(SetComboBoxSelectedValue)(DWORD dwFieldID, DWORD dwSelectedItem);
    STDMETHOD(CommandLinkClicked)(DWORD dwFieldID);
    STDMETHOD(GetSerialization)(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                               CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                               PWSTR* ppwszOptionalStatusText,
                               CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    STDMETHOD(ReportResult)(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                           PWSTR* ppwszOptionalStatusText,
                           CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2
    STDMETHOD(GetUserSid)(PWSTR* ppszSid);
    STDMETHOD(GetFieldOptions)(DWORD dwFieldID,
                              CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo);

    // Constructor and Destructor
    CSampleCredential();
    ~CSampleCredential();

    // Initialization
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                      const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                      const FIELD_STATE_PAIR* rgfsp,
                      ICredentialProviderUser* pcpUser);

private:
    // Biometric authentication methods
    HRESULT CaptureKeystrokeTiming(PCWSTR pwzOldValue, PCWSTR pwzNewValue);
    HRESULT SendBiometricDataToAI(bool* pbAuthenticated);
    HRESULT ProcessBiometricData();
    HRESULT ValidateBiometricData();
    
    // Credential serialization methods
    HRESULT GetUserCredentials(PWSTR* ppwzUsername, PWSTR* ppwzPassword, PWSTR* ppwzDomain);
    HRESULT PackageCredentials(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    
    // Helper methods
    HRESULT ResetBiometricData();
    HRESULT SecureMemoryCleanup();
    HRESULT LoadConfiguration();
    HRESULT UpdateStatusText(PCWSTR pszStatus);
    
    // Member variables
    LONG m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* m_rgCredProvFieldDescriptors;
    FIELD_STATE_PAIR* m_rgFieldStatePairs;
    PWSTR* m_rgFieldStrings;
    ICredentialProviderUser* m_pCredProvUser;
    PWSTR m_pszUserSid;
    PWSTR m_pszUsername;
    PWSTR m_pszPassword;
    PWSTR m_pszDomain;
    ICredentialProviderCredentialEvents* m_pCredProvCredentialEvents;
    
    // Biometric data
    BiometricProfile m_biometricProfile;
    LONGLONG m_performanceFrequency;
    LONGLONG m_lastKeystrokeTime;
    LONGLONG m_firstKeystrokeTime;
    BOOL m_bBiometricCaptureActive;
    BOOL m_bFirstKeystroke;
    BOOL m_bKeystrokeAnalysisComplete;
    BOOL m_bAIAuthenticationPassed;
    AIResponse m_aiResponse;
    
    // Configuration
    std::wstring m_strAIEndpoint;
    std::wstring m_strAPIKey;
    DWORD m_dwTimeout;
    BOOL m_bDebugMode;
    
    // Thread safety
    CRITICAL_SECTION m_cs;
    BOOL m_bCriticalSectionInitialized;
    
    // Status tracking
    BOOL m_bSelected;
    BOOL m_bSubmitClicked;
    NTSTATUS m_ntsLastResult;
};
