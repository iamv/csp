#pragma once
#include <iostream>
#include <Windows.h>
#include "common.h"
#include "CSPException.h"

class ProviderParamsConverter
{
public: 
	enum ContainerOperation{Open, WithoutContainer, Create, Delete};

private:
	bool m_isSilent;
	bool m_isMachineKeySet;
	DWORD m_ProvType;
	std::string m_ProvName;
	ContainerOperation m_operation;
public:
	ProviderParamsConverter(DWORD param, PVTableProvStruc table)
	{
		if(table->pszProvName==NULL)
			throw ::ErrorInvalidParameter();

		size_t provNameLen = strlen(table->pszProvName);
		
		if(provNameLen>MAX_PATH)
			throw ::ErrorInvalidParameter();

		if(provNameLen<1)
			throw ::ErrorInvalidParameter();

		m_ProvName = table->pszProvName;

		if(table->dwProvType==0)
			throw ::ErrorInvalidParameter();
		m_ProvType = table->dwProvType;

		m_isSilent = (param & CRYPT_SILENT)!=0;
		m_isMachineKeySet = (param & CRYPT_MACHINE_KEYSET)!=0;
		
		DWORD operation = param & ~CRYPT_SILENT;
		operation = operation & ~CRYPT_MACHINE_KEYSET;
		
		switch(operation)
		{
		case 0:						m_operation = Open; break;
		case CRYPT_VERIFYCONTEXT:	m_operation = WithoutContainer; break;
		case CRYPT_NEWKEYSET:		m_operation = Create; break;
		case CRYPT_DELETEKEYSET:	m_operation = Delete; break;
		default: throw ::NteBadFlags(); break;
		}
	}

	bool IsSilent() const
	{
		return m_isSilent;
	}
	bool IsMachineKeySet() const
	{
		return m_isMachineKeySet;
	}
	DWORD GetProvType() const
	{
		return m_ProvType;
	}
	void GetProvName(std::string& name) const
	{
		name = m_ProvName;
	}
	ContainerOperation GetOperation() const
	{
		return m_operation;
	}
};