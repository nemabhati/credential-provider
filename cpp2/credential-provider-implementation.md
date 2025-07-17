# Windows Credential Provider with Two-Stage Authentication

## Overview

This implementation provides a Windows Credential Provider that follows the exact authentication flow you requested:

1. **First Stage**: Authenticate username/password using KerbInteractiveUnlockLogonPack
2. **Second Stage**: If password authentication succeeds, send keystroke data to AI model
3. **Final Decision**: Only if both authentications succeed, allow user to enter system

## Key Implementation Details

### Authentication Flow
- Standard Windows authentication using KERB_INTERACTIVE_UNLOCK_LOGON
- Keystroke timing capture during password entry
- AI model integration via HTTPS
- Proper serialization with CPGSR_RETURN_CREDENTIAL_FINISHED

### Keystroke Data Format
The system captures and sends to your AI model:
- `key`: The actual character typed
- `keyDownTime`: High-resolution timestamp when key is pressed
- `keyUpTime`: High-resolution timestamp when key is released
- `position`: Position of keystroke in password sequence

### JSON Payload to AI Model
```json
{
    "keystrokes": [
        {
            "key": "a",
            "keyDownTime": 1234567890,
            "keyUpTime": 1234567950,
            "position": 0
        }
    ],
    "passwordLength": 8,
    "totalTypingTime": 2500,
    "username": "user@domain.com"
}
```

## Security Features

### Memory Protection
- Secure memory allocation for keystroke data
- Automatic cleanup of sensitive information
- Protection against memory dumps

### Network Security
- HTTPS communication with AI model
- Certificate validation
- Secure API key handling

### Thread Safety
- Critical section protection
- Proper synchronization for concurrent access
- Safe handling of shared resources

## Configuration

### Registry Settings
```
HKEY_LOCAL_MACHINE\SOFTWARE\BiometricCredentialProvider
- AIEndpoint: "https://your-ai-model.com/api/authenticate"
- APIKey: "your-secure-api-key"
- Timeout: 30000 (milliseconds)
- Enabled: 1
```

### Installation
1. Copy DLL to System32 directory
2. Register COM component with regsvr32
3. Add registry entries for credential provider
4. Configure AI model endpoint and API key
5. Restart system to activate

## Usage Flow

1. User enters username and password
2. System captures keystroke timing data
3. On submit, Windows validates credentials first
4. If Windows auth succeeds, send keystroke data to AI
5. If AI responds "legitimate", complete authentication
6. If either stage fails, deny access

This implementation ensures security by validating actual credentials before adding the behavioral biometric layer.