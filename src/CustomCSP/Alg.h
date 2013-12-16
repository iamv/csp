#pragma once
#include <Windows.h>
#include <WinCrypt.h>
#include "CSPException.h"

class Key;

class IAlg
{
private:
	ALG_ID m_id;
	DWORD m_defaultLen; 
	DWORD m_minLen; 
	DWORD m_maxLen; 
	DWORD m_protocols; 
	DWORD m_nameLen; 
	WCHAR m_name[20]; 
	DWORD m_longNameLen;
	WCHAR m_longName[40];
public:
	IAlg(ALG_ID id, DWORD defaultLen, DWORD minLen, DWORD maxLen, DWORD protocols, const std::wstring& name, const std::wstring& longName)
		: m_id(id), m_defaultLen(defaultLen), m_minLen(minLen), m_maxLen(maxLen), m_protocols(protocols)
	{
		{
			size_t lenName = std::min<size_t>(name.length(), 19);//TODO: заменить на константы
			for(size_t i=0; i < lenName; ++i)
				m_name[i]=name[i];
			m_name[lenName] = '\0';
			m_nameLen = lenName;
		}

		{
			size_t lenLongName = std::min<size_t>(longName.length(), 39);//TODO: заменить на константы
			for(size_t i=0; i < lenLongName; ++i)
				m_longName[i]=longName[i];
			m_longName[lenLongName] = '\0';
			m_longNameLen = lenLongName;
		}
	}
	virtual ~IAlg()
	{
	}
	ALG_ID GetId() const
	{
		return m_id;
	}
	void GetProvEnumAlgs(BYTE* buffer, DWORD* bufferSize)
	{
		DWORD structSize = sizeof(PROV_ENUMALGS);
		
		if(buffer==NULL)
		{
			*bufferSize = structSize;
			return;
		}

		if(*bufferSize < structSize)
			throw ::ErrorMoreData();

		PROV_ENUMALGS tmp;
		tmp.aiAlgid = m_id;
		tmp.dwBitLen = m_defaultLen;
		tmp.dwNameLen = m_nameLen;
		memcpy(tmp.szName, m_name, m_nameLen);
		memcpy(buffer, &tmp, sizeof(tmp));
	}
	void GetProvEnumAlgsEx(BYTE* buffer, DWORD* bufferSize)
	{
		DWORD structSize = sizeof(PROV_ENUMALGS_EX);
		
		if(buffer==NULL)
		{
			*bufferSize = structSize;
			return;
		}

		if(*bufferSize < structSize)
			throw ::ErrorMoreData();

		PROV_ENUMALGS_EX tmp;
		tmp.aiAlgid = m_id;
		tmp.dwDefaultLen = m_defaultLen;
		tmp.dwLongNameLen = m_longNameLen;
		tmp.dwMaxLen = m_maxLen;
		tmp.dwMinLen = m_minLen;
		tmp.dwNameLen = m_nameLen;
		tmp.dwProtocols = m_protocols;
		memcpy(tmp.szLongName, m_longName, m_longNameLen);
		memcpy(tmp.szName, m_name, m_nameLen);

		memcpy(buffer, &tmp, sizeof(tmp));
	}
	virtual DWORD GetIncrementKeySize() const =0;
	virtual Key* CreateKey(DWORD size, bool salt, bool exportable) const =0;
	virtual Key* ImportKey(const BYTE* blob, DWORD size) const =0; 
};