// CSPTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Loader.h"
#include "Test.h"


int _tmain()
{
	Loader load;

	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	pVTable->pszProvName = "Test CSP";
	pVTable->dwProvType = 1;
	if(load.AcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
		return NULL;
	return 0;
}

