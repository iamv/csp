#pragma once
#include <Windows.h>
#include <WinCrypt.h>

//general information about provider
class ProviderInfo
{
public:
	static DWORD GetVersion()
	{
		return 0x00000001;
	}
	static DWORD GetImplementation()
	{
		return CRYPT_IMPL_SOFTWARE; 
	}
	static ALG_ID GetDefaultKeyXAlg()
	{
		return CALG_RSA_KEYX;
	}
	static ALG_ID GetDefaultSignAlg()
	{
		return CALG_RSA_SIGN;
	}

};