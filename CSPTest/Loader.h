#pragma once
#include "stdafx.h"

typedef BOOL (WINAPI *CRYPT_VERIFY_IMAGE_A)(LPCSTR  szImage, CONST BYTE *pbSigData);
typedef void (*CRYPT_RETURN_HWND)(HWND *phWnd);
typedef struct _VTableProvStruc {
    DWORD                Version;
    CRYPT_VERIFY_IMAGE_A FuncVerifyImage;
    CRYPT_RETURN_HWND    FuncReturnhWnd;
    DWORD                dwProvType;
    BYTE                *pbContextInfo;
    DWORD                cbContextInfo;
    LPSTR                pszProvName;
} VTableProvStruc,      *PVTableProvStruc;

typedef BOOL (WINAPI *PAcquireContext)(HCRYPTPROV* phProv, CHAR* pszContainer, DWORD dwFlags, PVTableProvStruc pVTable); 
typedef BOOL (WINAPI *PReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);

class Loader
{
	public:
	PAcquireContext AcquireContext;
	PReleaseContext ReleaseContext;
private:
	void Load()
	{
		HMODULE dll = LoadLibrary(L"CustomCSP.dll");
		if(dll!=NULL)
		{
			AcquireContext = (PAcquireContext)GetProcAddress(dll, "CPAcquireContext");
			ReleaseContext = (PReleaseContext)GetProcAddress(dll, "CPReleaseContext");
		}
	
	}
public:
	Loader()
	{
		Load();
	}
	
};