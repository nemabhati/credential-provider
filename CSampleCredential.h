#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <unknwn.h>
#include <strsafe.h>
#include <shlwapi.h>
#include "common.h"

class CSampleCredential : public ICredentialProviderCredential2, public ICredentialProviderCredentialEvents
{
public:
    CSampleCredential();
    virtual ~CSampleCredential();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();

    // ICredentialProviderCredential
    STDMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    STDMETHODIMP UnAdvise();
    STDMETHODIMP SetSelected(BOOL* pbAutoLogon);
    STDMETHODIMP SetDeselected();
    STDMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    STDMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    STDMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    STDMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    STDMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    STDMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    STDMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    STDMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    STDMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    STDMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    STDMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    STDMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    STDMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2
    STDMETHODIMP GetUserSid(PWSTR* ppszSid);

    // ICredentialProviderCredentialEvents
    STDMETHODIMP OnCreatingWindow(HWND* phwndOwner);
    STDMETHODIMP SetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS options);
    STDMETHODIMP SetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE cpfs);
    STDMETHODIMP SetFieldInteractiveState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis);
    STDMETHODIMP SetFieldString(DWORD dwFieldID, PCWSTR pwz);
    STDMETHODIMP SetFieldCheckbox(DWORD dwFieldID, BOOL bChecked, PCWSTR pwzLabel);
    STDMETHODIMP SetFieldBitmap(DWORD dwFieldID, HBITMAP hbmp);
    STDMETHODIMP SetFieldComboBoxSelectedItem(DWORD dwFieldID, DWORD dwSelectedItem);
    STDMETHODIMP DeleteFieldComboBoxItem(DWORD dwFieldID, DWORD dwItem);
    STDMETHODIMP AppendFieldComboBoxItem(DWORD dwFieldID, PCWSTR pwzItem);
    STDMETHODIMP SetFieldSubmitButton(DWORD dwFieldID, DWORD dwAdjacentTo);
    STDMETHODIMP OnFieldChanged(DWORD dwFieldID);

    // Initialization
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, 
                      const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd, 
                      const FIELD_STATE_PAIR* rgfsp, 
                      ICredentialProviderUser* pcpUser);

private:
    // Keystroke capture methods
    HRESULT _CaptureKeystroke(PCWSTR pwzOldValue, PCWSTR pwzNewValue);
    HRESULT _ProcessKeystrokeData();
    HRESULT _AnalyzeKeystrokePattern();
    HRESULT _SendBiometricDataToAI();
    HRESULT _ProcessAIResponse(const std::wstring& response);
    
    // Authentication methods
    HRESULT _AuthenticateUser(BOOL* pbAuthenticated);
    HRESULT _GetUserCredentials(PWSTR* ppwszUsername, PWSTR* ppwszPassword, PWSTR* ppwszDomain);
    HRESULT _PackageCredentials(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    
    // Helper methods
    HRESULT _ClearFields();
    HRESULT _ResetBiometricData();
    HRESULT _UpdateStatusField(PCWSTR pwzStatus);
    HRESULT _GetFieldString(DWORD dwFieldID, PWSTR* ppwsz);
    HRESULT _SetFieldString(DWORD dwFieldID, PCWSTR pwz);
    
    // Timing methods
    HRESULT _StartKeystrokeCapture();
    HRESULT _StopKeystrokeCapture();
    HRESULT _GetCurrentTimestamp(LARGE_INTEGER* pTimestamp);
    
    // Security methods
    HRESULT _SecureMemoryCleanup();
    HRESULT _ValidateInput(PCWSTR pwzInput);

private:
    LONG m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    
    // Field descriptors and states
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* m_rgCredProvFieldDescriptors;
    FIELD_STATE_PAIR* m_rgFieldStatePairs;
    PWSTR* m_rgFieldStrings;
    
    // User information
    ICredentialProviderUser* m_pCredProvUser;
    PWSTR m_pszUserSid;
    PWSTR m_pszUsername;
    PWSTR m_pszPassword;
    PWSTR m_pszDomain;
    
    // Event handling
    ICredentialProviderCredentialEvents* m_pCredProvCredentialEvents;
    
    // Biometric data
    BiometricProfile m_biometricProfile;
    BOOL m_bBiometricCaptureActive;
    BOOL m_bKeystrokeAnalysisComplete;
    BOOL m_bAIAuthenticationPassed;
    
    // Timing
    LARGE_INTEGER m_performanceFrequency;
    LARGE_INTEGER m_lastKeystrokeTime;
    LARGE_INTEGER m_firstKeystrokeTime;
    BOOL m_bFirstKeystroke;
    
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
    
    // AI response
    AIResponse m_aiResponse;
};

// Helper functions
HRESULT CSampleCredential_CreateInstance(REFIID riid, void** ppv);
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);
HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, KERB_INTERACTIVE_UNLOCK_LOGON* pkiul);
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn, BYTE** prgb, DWORD* pcb);
void KerbInteractiveUnlockLogonUnpackInPlace(KERB_INTERACTIVE_UNLOCK_LOGON* pkiul, DWORD cb);

// Constants
#define MAX_FIELD_STRING_LENGTH 512
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256
#define MAX_DOMAIN_LENGTH 256
#define MAX_SID_LENGTH 256

// Timing constants
#define KEYSTROKE_TIMEOUT_MS 5000
#define AI_REQUEST_TIMEOUT_MS 30000
#define MIN_PASSWORD_LENGTH 1
#define MAX_KEYSTROKE_COUNT 256