#pragma once

#include "common.h"

// DLL reference counting
void DllAddRef();
void DllRelease();

// Standard COM exports
STDAPI DllCanUnloadNow();
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv);
STDAPI DllRegisterServer();
STDAPI DllUnregisterServer();

// Global variables
extern HINSTANCE g_hInst;
extern LONG g_cRef;
