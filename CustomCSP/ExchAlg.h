#pragma once 

#include "Alg.h"

class ExchAlg : public IAlg
{
	ExchAlg(ALG_ID id, DWORD defaultLen, DWORD minLen, DWORD maxLen, DWORD protocols, const std::wstring& name, const std::wstring& longName): IAlg(id, defaultLen, minLen, maxLen, protocols, name, longName)
	{
	}
	virtual ~ExchAlg()
	{
	}
};