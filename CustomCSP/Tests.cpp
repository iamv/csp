#include "stdafx.h"
#include "csp.h"
#include <vector>
#include <WinCrypt.h>


HCRYPTPROV CrateGoodHanle()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	pVTable->pszProvName = "Test CSP";
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
		return NULL;
	return phProv;
}
HCRYPTPROV CreateTest5()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	pVTable->pszProvName = "Test CSP";
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
		return NULL;
	return phProv;
}
void ClearTestResalt()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = CRYPT_DELETEKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	pVTable->pszProvName = "Test CSP";
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
		return; 
}
DWORD Test_CPReleaseContext()
{
	HCRYPTPROV phProv = CrateGoodHanle();
	if(phProv==NULL)
		return FALSE;
	
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}

DWORD TestBadProvHandle_CPReleaseContext()
{
	HCRYPTPROV phProv = NULL;
	if(CPReleaseContext(phProv, 0)==FALSE)
	{
		DWORD code = GetLastError();
		if(code==NTE_BAD_UID)
			return TRUE;
		else 
			return code;
	}
	return FALSE;
}

DWORD TestDoubleCall_CPReleaseContext()
{
	HCRYPTPROV phProv = CrateGoodHanle();
	if(phProv==NULL)
		return FALSE;
	
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	
	if(CPReleaseContext(phProv, 0)==TRUE)
		return FALSE;

	DWORD code = GetLastError();
	if(code!=NTE_BAD_UID)
		return code;
	
	return TRUE;
}

DWORD TestBadFlags_CPReleaseContext()
{
	HCRYPTPROV phProv = CrateGoodHanle();
	if(phProv==NULL)
		return FALSE;
	
	if(CPReleaseContext(phProv, 0xFF)==TRUE)
		return FALSE;

	DWORD code = GetLastError();
	if(code!=NTE_BAD_FLAGS)
		return code;

	return TRUE;
	
}

DWORD Test_CPAcquireContext()
{
	HCRYPTPROV phProv = CrateGoodHanle();
	if(phProv==NULL)
		return FALSE;
	
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();

	return TRUE;
}

DWORD TestBadBigProvName()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char name[MAX_PATH+2];
	for(int i=0; i <MAX_PATH+1; ++i)
		name[i]='a';
	name[MAX_PATH+1] = 0;
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code == ERROR_INVALID_PARAMETER)
		return TRUE;
	return code;

}
DWORD TestGoodBigProvName()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char name[MAX_PATH+1];
	for(int i=0; i <MAX_PATH; ++i)
		name[i]='a';
	name[MAX_PATH] = 0;
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
		return GetLastError();
	
	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
	
	return TRUE;
}

DWORD TestBadEmptyProvName()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char name[] = "";
	
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code == ERROR_INVALID_PARAMETER)
		return TRUE;
	return code;
}

DWORD TestBadNULLProvName()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "Test5";
	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = NULL;
	
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code == ERROR_INVALID_PARAMETER)
		return TRUE;
	return code;
}

DWORD TestBadEmptyContName()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = "";
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";
	
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code == ERROR_INVALID_PARAMETER)
		return TRUE;
	return code;
}

DWORD TestNULLContName()
{
	HCRYPTPROV phProv = NULL;
	CHAR* pszContainer = NULL;
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";
	
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
		return GetLastError(); //Сейчас не реализована функция возврата дефолтного контейнера
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();

	DWORD flag2 = CRYPT_DELETEKEYSET;
	CPAcquireContext(&phProv, pszContainer, flag2, pVTable);
	return TRUE;
}

DWORD TestBadBigContName()
{
	HCRYPTPROV phProv = NULL;
	CHAR pszContainer[MAX_PATH+2];
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	for(int i = 0; i < MAX_PATH+1; ++i)
		pszContainer[i]='b';
	pszContainer[MAX_PATH+1]=0;
	
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code == ERROR_INVALID_PARAMETER)
		return TRUE;
	return code;
}

DWORD TestGoodBigContName()
{
	HCRYPTPROV phProv = NULL;
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	std::vector<CHAR> container;
	for(int i = 0; i < MAX_PATH-10; ++i)
		container.push_back('c');
	container.push_back(0);
	
	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
	{
		return GetLastError();
	}

	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	
	DWORD flag2 = CRYPT_DELETEKEYSET;
	CPAcquireContext(&phProv, &container[0], flag2, pVTable);

	return TRUE;
}

DWORD TestShortContName()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "1";
	std::vector<CHAR> container(nameKey.begin(), nameKey.end());
	container.push_back(0);
	
	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
	{
		return GetLastError();
	}

	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
		
	DWORD flag2 = CRYPT_DELETEKEYSET;
	CPAcquireContext(&phProv, &container[0], flag2, pVTable);
	return TRUE;
}

DWORD TestNullProvType()
{
	HCRYPTPROV phProv = NULL;
	CHAR pszContainer[2];
	pszContainer[0]='b';
	pszContainer[1]=0;
	
	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = NULL;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code!=ERROR_INVALID_PARAMETER)
		return code;
		
	return TRUE;
}

DWORD TestBadFlag()
{
	HCRYPTPROV phProv = NULL;
	CHAR pszContainer[2];
	pszContainer[0]='b';
	pszContainer[1]=0;
	
	DWORD flag = 0xffff;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code!=NTE_BAD_FLAGS)
		return code;
		
	return TRUE;
}

DWORD TestBadCombinationFlag()
{
	HCRYPTPROV phProv = NULL;
	CHAR pszContainer[2];
	pszContainer[0]='b';
	pszContainer[1]=0;
	
	DWORD flag = CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, pszContainer, flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code!=NTE_BAD_FLAGS)
		return code;
		
	return TRUE;
}

DWORD TestNewKeySetFlag()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test56";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();

	CPAcquireContext(&phProv, &container[0], CRYPT_DELETEKEYSET, pVTable);
		
	return TRUE;
}

DWORD TestOpenKeySetFlag()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		
	return TRUE;
}

DWORD TestDeleteKeySetFlag()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = CRYPT_DELETEKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)==TRUE)
			return FALSE;

	DWORD code = GetLastError();
	if(code!=NTE_BAD_UID)
		return code;
	
	return TRUE;
}

DWORD TestVerifyKeyFlag()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = CRYPT_VERIFYCONTEXT;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		
	return TRUE;
}

DWORD TestDoubleCreateNewKey()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = CRYPT_NEWKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)==TRUE)
	{
		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}
	DWORD code = GetLastError();
	if(code!=NTE_EXISTS)
		return code;

	return TRUE;
}


DWORD TestDoubleDeleteKeySetFlag()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = CRYPT_DELETEKEYSET;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)==TRUE)
			return FALSE;

	DWORD code = GetLastError();
	if(code!=NTE_BAD_UID)
		return code;
	
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)==TRUE)
			return false;

	DWORD codeDel = GetLastError(); 
	if(codeDel!=NTE_KEYSET_NOT_DEF)
		return codeDel;

	if(CPAcquireContext(&phProv, &container[0], CRYPT_NEWKEYSET, pVTable)!=TRUE)
			return GetLastError();

	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();


	return TRUE;
}

DWORD TestOpenBadKeySetFlag()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "D://NoCreate.key";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)==TRUE)
	{

		if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
		return FALSE;
	}

	DWORD code = GetLastError();
	if(code!=NTE_KEYSET_NOT_DEF)
		return code;

	return TRUE;
}

DWORD GetProvParametrBadUID(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	DWORD sizeBuffer = 0;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, NULL)==TRUE)
		return FALSE;
	DWORD code = GetLastError();
	if(code!=NTE_BAD_UID)
		return code;
	return TRUE;
}

DWORD GetProvParametrGedSizeBuffer(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, NULL)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}
	if(sizeBuffer==0)
		return FALSE;
	
	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
	
	return TRUE;
}

DWORD GetProvParametrSmallBuffer(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, NULL)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}
	if(sizeBuffer==0)
		return FALSE;
	sizeBuffer--;
	std::vector<BYTE> buff(sizeBuffer);
	if(CPGetProvParam(phProv, param, &buff[0], &sizeBuffer, NULL)==TRUE)
	{
		CPReleaseContext(phProv, 0);
		return FALSE;
	}
	DWORD code = GetLastError();
	if(code!=ERROR_MORE_DATA)
	{
		CPReleaseContext(phProv, 0);
		return code;
	}
	
	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
	
	return TRUE;
}


DWORD GetProvParametrBigBuffer(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, param == 2 ? CRYPT_FIRST : NULL)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}
	if(sizeBuffer==0)
		return FALSE;
	sizeBuffer++;
	std::vector<BYTE> buff(sizeBuffer);

	if(CPGetProvParam(phProv, param, &buff[0], &sizeBuffer, param == 2 ? CRYPT_FIRST : NULL)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	
	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
	
	return TRUE;
}

DWORD GetProvParametrCorrectBuffer(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, param == 2 ? CRYPT_FIRST : NULL)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}
	if(sizeBuffer==0)
		return FALSE;

	std::vector<BYTE> buff(sizeBuffer);

	if(CPGetProvParam(phProv, param, &buff[0], &sizeBuffer, param == 2 ? CRYPT_FIRST : NULL)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	
	if(CPReleaseContext(phProv, 0)!=TRUE)
			return GetLastError();
	
	return TRUE;
}

DWORD GetProvParametrBadParam()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	if(CPGetProvParam(phProv, 0xff, NULL, &sizeBuffer, NULL)==TRUE)
	{
		CPReleaseContext(phProv, 0);
		return FALSE;
	}

	DWORD code = GetLastError();
	
	CPReleaseContext(phProv, 0);
	if(code!=NTE_BAD_TYPE)
		return code;
	return TRUE;
}

DWORD GetProvParametrBadFlag(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	DWORD flags = 0xff;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, flags)==TRUE)
	{
		CPReleaseContext(phProv, 0);
		return FALSE;
	}

	DWORD code = GetLastError();
	
	CPReleaseContext(phProv, 0);
	if(code!=NTE_BAD_FLAGS)
		return code;
	return TRUE;
}

DWORD GetProvParametrGoodFlag(DWORD param, DWORD flagParam)
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	DWORD sizeBuffer = 0;
	DWORD flags = flagParam;
	if(CPGetProvParam(phProv, param, NULL, &sizeBuffer, flags)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}
	std::vector<BYTE> buff(sizeBuffer);
	if(CPGetProvParam(phProv, param, &buff[0], &sizeBuffer, flags)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}

DWORD Test_CPGenRandom()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	std::vector<BYTE> buff(4000);
	if(CPGenRandom(phProv, buff.size(), &buff[0])!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}

DWORD TestBadUID_CPGenRandom()
{
	HCRYPTPROV phProv = NULL;
	std::vector<BYTE> buff(4000);
	if(CPGenRandom(phProv, buff.size(), &buff[0])==TRUE)
		return FALSE;

	DWORD code = GetLastError();
	if(code!=NTE_BAD_UID)
		return code;

	return TRUE;
}

DWORD TestBadUID_CPGetUserKey(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	HCRYPTKEY key = NULL;
	if(CPGetUserKey(phProv, param, &key)==TRUE)
		return FALSE;

	DWORD code = GetLastError();
	if(code!=NTE_BAD_UID)
		return code;

	return TRUE;
}

DWORD TestBadSpecify_CPGetUserKey()
{
	HCRYPTPROV phProv = NULL;
	HCRYPTKEY key = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	if(CPGetUserKey(phProv, 0xff, &key)==TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	DWORD code = GetLastError();
	if(code!=NTE_BAD_KEY)
	{
		CPReleaseContext(phProv, 0);
		return code;
	}
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}

DWORD TestEmptyContainer_CPGetUserKey(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	HCRYPTKEY key = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	if(CPGetUserKey(phProv, param, &key)==TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	DWORD code = GetLastError();
	if(code!=NTE_NO_KEY)
	{
		CPReleaseContext(phProv, 0);
		return code;
	}
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}

DWORD TestVERIFYCONTEXT_CPGetUserKey(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	HCRYPTKEY key = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	if(CPGetUserKey(phProv, param, &key)==TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	DWORD code = GetLastError();
	if(code!=NTE_NO_KEY)
	{
		CPReleaseContext(phProv, 0);
		return code;
	}
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}

DWORD TestCorrect_CPGetUserKey(DWORD param)
{
	HCRYPTPROV phProv = NULL;
	HCRYPTKEY key = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	if(CPGetUserKey(phProv, param, &key)!=TRUE)
	{
		CPReleaseContext(phProv, 0);
		return GetLastError();
	}

	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	return TRUE;
}
DWORD TestBadUID_CPCreateHash()
{
	return FALSE;
}
DWORD TestBadALGID_CPCreateHash()
{
	return FALSE;
}
DWORD TestBadKey_CPCreateHash()
{
	return FALSE;
}
DWORD TestBadFlag_CPCreateHash()
{
	return FALSE;
}
DWORD TestGoodAlgID_CPCreateHash()
{
	return FALSE;
}
DWORD TestGoodKey_CPCreateHash()
{
	return FALSE;
}
DWORD TestNullKey_CPCreateHash()
{
	return FALSE;
}

DWORD TestCreateHash()
{
	HCRYPTPROV phProv = NULL;
	std::string nameKey = "Test5";
	std::vector<char> container(nameKey.begin(), nameKey.end()); 
	container.push_back(0);

	DWORD flag = 0;
	PVTableProvStruc pVTable = new VTableProvStruc();
	
	char* name = "Test CSP";

	pVTable->pszProvName = name;
	pVTable->dwProvType = 1;
	if(CPAcquireContext(&phProv, &container[0], flag, pVTable)!=TRUE)
		return GetLastError();

	HCRYPTHASH hash;
	DWORD code = TRUE;
	if(CPCreateHash(phProv, CALG_MD5, NULL, NULL, &hash)!=TRUE)
		return GetLastError();
	HCRYPTHASH hash2 = NULL;
	
	if(code==TRUE && CPDuplicateHash(phProv, hash, NULL, 0, &hash2)!=TRUE)
		code = GetLastError();
	else
		if(CPDestroyHash(phProv, hash2)!=TRUE)
			code = GetLastError();
	
	ALG_ID id = 1;
	DWORD idSize = 0;
	if(code && CPGetHashParam(phProv, hash, HP_ALGID, NULL, &idSize, 0)!=TRUE)
		code = GetLastError();
	if(code && CPGetHashParam(phProv, hash, HP_ALGID, (BYTE*)&id, &idSize, 0)!=TRUE)
		code = GetLastError();

	DWORD len = 1;
	DWORD lenSize = 0;
	if(code &&CPGetHashParam(phProv, hash, HP_HASHSIZE, NULL, &lenSize, 0)!=TRUE)
		code = GetLastError();
	if(code &&CPGetHashParam(phProv, hash, HP_HASHSIZE, (BYTE*)&len, &lenSize, 0)!=TRUE)
		code = GetLastError();

	std::vector<BYTE> val;
	DWORD valSize = 0;
	if(code &&CPGetHashParam(phProv, hash, HP_HASHVAL, NULL, &valSize, 0)!=TRUE)
		code = GetLastError();
	val.resize(valSize);
	if(code &&CPGetHashParam(phProv, hash, HP_HASHVAL, &val[0], &valSize, 0)!=TRUE)
		code = GetLastError();
	//TODO: добавить HP_HMAC_INFO

	if(CPDestroyHash(phProv, hash)!=TRUE)
		code = GetLastError();
	if(CPReleaseContext(phProv, 0)!=TRUE)
		return GetLastError();
	
	return code;
}

void PrintResult(DWORD error)
{
	if(error==1)
		system("color 07");
	else
		system("color 0C");
}
void TestCSP()
{
	ClearTestResalt();
	CreateTest5();
	//Test CPReleaseContext()
	std::cout<<1<<"  CPReleaseContext: "<<Test_CPReleaseContext()<<std::endl;
	std::cout<<2<<"  CPReleaseContext: "<<TestBadProvHandle_CPReleaseContext()<<std::endl;
	std::cout<<3<<"  CPReleaseContext: "<<TestDoubleCall_CPReleaseContext()<<std::endl;
	std::cout<<4<<"  CPReleaseContext: "<<TestBadFlags_CPReleaseContext()<<std::endl;
	//Test CPAcquireContext
	std::cout<<5<<"  CPAcquireContext: "<<Test_CPAcquireContext()<<std::endl;
	std::cout<<6<<"  CPAcquireContext: "<<TestBadBigProvName()<<std::endl;
	std::cout<<7<<"  CPAcquireContext: "<<TestGoodBigProvName()<<std::endl;
	std::cout<<8<<"  CPAcquireContext: "<<TestBadEmptyProvName()<<std::endl;
	std::cout<<9<<"  CPAcquireContext: "<<TestBadNULLProvName()<<std::endl;
	
	//Тесты на контейнер не работают корректно.
	std::cout<<10<<" CPAcquireContext: "<<TestBadEmptyContName()<<std::endl;
	std::cout<<11<<" CPAcquireContext: "<<TestNULLContName()<<std::endl;
	std::cout<<12<<" CPAcquireContext: "<<TestBadBigContName()<<std::endl;
	std::cout<<13<<" CPAcquireContext: "<<TestGoodBigContName()<<std::endl;
	std::cout<<14<<" CPAcquireContext: "<<TestShortContName()<<std::endl;
	std::cout<<15<<" CPAcquireContext: "<<TestBadEmptyContName()<<std::endl;

	std::cout<<16<<" CPAcquireContext: "<<TestNullProvType()<<std::endl;
	std::cout<<17<<" CPAcquireContext: "<<TestBadFlag()<<std::endl;
	std::cout<<18<<" CPAcquireContext: "<<TestBadCombinationFlag()<<std::endl;

	std::cout<<19<<" CPAcquireContext: "<<TestNewKeySetFlag()<<std::endl;
	std::cout<<20<<" CPAcquireContext: "<<TestOpenKeySetFlag()<<std::endl;
	std::cout<<21<<" CPAcquireContext: "<<TestDeleteKeySetFlag()<<std::endl;
	std::cout<<22<<" CPAcquireContext: "<<TestVerifyKeyFlag()<<std::endl;
	
	std::cout<<23<<" CPAcquireContext: "<<TestDoubleCreateNewKey()<<std::endl;
	std::cout<<24<<" CPAcquireContext: "<<TestDoubleDeleteKeySetFlag()<<std::endl;
	std::cout<<25<<" CPAcquireContext: "<<TestOpenBadKeySetFlag()<<std::endl;
	//TODO: case с режимом SILENT

	//TODO: не забыть раскомментить параметры
	std::vector<DWORD> paramList;
	//PP_ADMIN_PIN
	//PP_CERTCHAIN
	paramList.push_back(PP_CONTAINER);
	//paramList.push_back(PP_ENUMALGS);
	//paramList.push_back(PP_ENUMALGS_EX);
	paramList.push_back(PP_ENUMCONTAINERS);
	//PP_ENUMEX_SIGNING_PROT
	paramList.push_back(PP_IMPTYPE);
	//PP_KEYEXCHANGE_PIN
	//PP_KEYSTORAGE
	//paramList.push_back(PP_KEYX_KEYSIZE_INC);
	//paramList.push_back(PP_KEYSET_SEC_DESCR);
	//PP_KEYSET_TYPE
	//PP_KEYSPEC
	paramList.push_back(PP_NAME);
	paramList.push_back(PP_PROVTYPE);
	//paramList.push_back(PP_ROOT_CERTSTORE);
	//paramList.push_back(PP_SIG_KEYSIZE_INC);
	//PP_SIGNATURE_PIN
	//PP_SESSION_KEYSIZE
	//paramList.push_back(PP_SMARTCARD_GUID);
	paramList.push_back(PP_UNIQUE_CONTAINER);
	//PP_SYM_KEYSIZE
	//paramList.push_back(PP_USER_CERTSTORE);
	paramList.push_back(PP_VERSION);

	std::cout<<"BadUID"<<std::endl;
	int j = 26;
	std::vector<DWORD>::iterator param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrBadUID(*param)<<std::endl;
	
	std::cout<<"GetSizeBuffer"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrGedSizeBuffer(*param)<<std::endl;
	
	std::cout<<"BigBuffer"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrBigBuffer(*param)<<std::endl;
	
	std::cout<<"SmallBufer"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrSmallBuffer(*param)<<std::endl;
	
	std::cout<<"CorrectBufer"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrCorrectBuffer(*param)<<std::endl;
	
	std::cout<<"BadFlag"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrBadFlag(*param)<<std::endl;
	
	std::cout<<"BadParam"<<std::endl;
	std::cout<<j<<" CPGetProvParam: "<<GetProvParametrBadParam()<<std::endl;
	j++;

	std::cout<<"GoodFlag"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrGoodFlag(*param, 0)<<std::endl;
	
	std::cout<<"CryprtFirst"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrGoodFlag(*param, CRYPT_FIRST)<<std::endl;
	
	std::cout<<"MachineKeySet"<<std::endl;
	param = paramList.begin();
	for(;param!=paramList.end(); ++param, ++j)
		std::cout<<j<<" CPGetProvParam: "<<GetProvParametrGoodFlag(*param, CRYPT_MACHINE_KEYSET)<<std::endl;
	//TODO: сделать тест на перечисление
	//TODO: сделать case для CPSetProvParam
	
	//TODO: проработать полный test case для hash функций
	std::cout<<j++<<" CPCreateHash:"<<TestCreateHash()<<std::endl;

	std::cout<<j++<<" CPGenRandom: "<<Test_CPGenRandom()<<std::endl;
	std::cout<<j++<<" CPGenRandom: "<<TestBadUID_CPGenRandom()<<std::endl;
	
	std::vector<BYTE> specifyKey;
	specifyKey.push_back(AT_SIGNATURE);
	specifyKey.push_back(AT_KEYEXCHANGE);

	std::vector<BYTE>::iterator specKey = specifyKey.begin();
	for(;specKey!=specifyKey.end();++specKey, ++j)
	std::cout<<j++<<" CPGetUserKey: "<<TestBadUID_CPGetUserKey(*specKey)<<std::endl;
	
	specKey = specifyKey.begin();
	for(;specKey!=specifyKey.end();++specKey, ++j)
	std::cout<<j++<<" CPGetUserKey: "<<TestEmptyContainer_CPGetUserKey(*specKey)<<std::endl;
	
	specKey = specifyKey.begin();
	for(;specKey!=specifyKey.end();++specKey, ++j)
	std::cout<<j++<<" CPGetUserKey: "<<TestVERIFYCONTEXT_CPGetUserKey(*specKey)<<std::endl;

	specKey = specifyKey.begin();
	for(;specKey!=specifyKey.end();++specKey, ++j)
	std::cout<<j++<<" CPGetUserKey: "<<TestCorrect_CPGetUserKey(*specKey)<<std::endl;
	

	std::cout<<j++<<" CPGetUserKey: "<<TestBadSpecify_CPGetUserKey()<<std::endl;
	
}

