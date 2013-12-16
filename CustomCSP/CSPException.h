#pragma once
#include <Windows.h>

//TODO: подумать а не оставить ли один класс, который несет в себе код передаваемый в констукторе
class CSPException
{
public:
	virtual DWORD GetCode() = 0;
};

class NteBadUID: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_UID;
	}
};

class NteNoSupported : public CSPException
{
public: 
	DWORD GetCode()
	{
		return (DWORD)NTE_NOT_SUPPORTED;
	}
};

class NteBadHash :public CSPException
{
public: 
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_HASH;
	}
};

class NteBadFlags :public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_FLAGS;
	}
};

class NteBadKey: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_KEY;
	}
};

class NteFail: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_FAIL;
	}
};

class NteBadHashState: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_HASH_STATE;
	}
};

class NteBadAlgID: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_ALGID;
	}
};

class NteNoMemory : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_NO_MEMORY;
	}
};

class ErrorInvalidParameter: public CSPException
{
public:
	DWORD GetCode()
	{
		return ERROR_INVALID_PARAMETER;
	}
};

class NteBadType: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_TYPE;
	}
};

class ErrorMoreData : public CSPException
{
public:
	DWORD GetCode()
	{
		return ERROR_MORE_DATA;
	}
};

//class NteBadAlgID : public CSPException
//{
//public:
//	DWORD GetCode()
//	{
//		return NTE_BAD_ALGID;
//	}
//};


//class NteBadHash : public CSPException
//{
//public:
//	DWORD GetCode()
//	{
//		return NTE_BAD_HASH;
//	}
//};


class ErrorNoMoreItems : public CSPException
{
public:
	DWORD GetCode()
	{
		return ERROR_NO_MORE_ITEMS;
	}
};

class NteNoKey : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_NO_KEY;
	}
};

class NteBadSignature : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_SIGNATURE;
	}
};

class NteBadLen : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_LEN;
	}
};

class NteBadKeyState : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_KEY_STATE;
	}
};

class NteExists : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_EXISTS;
	}
};

class NteBadKeySet: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_KEYSET;
	}
};

class NteBadKeySetParam: public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_BAD_KEYSET_PARAM;
	}
};


class NteKeySetEntryBad : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_KEYSET_ENTRY_BAD;
	}
};

class NteKeySetNotDef:public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_KEYSET_NOT_DEF;
	}
};

class NteProviderDllFail : public CSPException
{
public:
	DWORD GetCode()
	{
		return (DWORD)NTE_PROVIDER_DLL_FAIL;
	}
};
