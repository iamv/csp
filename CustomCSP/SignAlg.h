#pragma once
#include "Alg.h"

class Hash;
class SignAlg: public IAlg
{
public:
	SignAlg(ALG_ID id, DWORD defaultLen, DWORD minLen, DWORD maxLen, DWORD protocols, const std::wstring& name, const std::wstring& longName): IAlg(id, defaultLen, minLen, maxLen, protocols, name, longName)
	{
	}
	virtual void Sign(const Hash*, const Key*, BYTE*, DWORD*) const =0;
	virtual void Verify(const Hash* hash, const Key *key,const BYTE* signData, DWORD signDataSize) const =0;
	virtual ~SignAlg()
	{
	}
};