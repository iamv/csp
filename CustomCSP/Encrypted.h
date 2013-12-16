#pragma once
#include <Windows.h>
#include "Alg.h"

//Интерфейс алгоритма шифрования
class EncrAlg : public IAlg
{
public:
	EncrAlg(ALG_ID id, DWORD defaultLen, DWORD minLen, DWORD maxLen, DWORD protocols, const std::wstring& name, const std::wstring& longName): IAlg(id, defaultLen, minLen, maxLen, protocols, name, longName)
	{
	}
	virtual ~EncrAlg()
	{
	}
	virtual void Encrypted(BYTE* buffer, DWORD* size, DWORD dataSize)=0;
	virtual void Decrypted(BYTE* data, DWORD* size)=0;
};