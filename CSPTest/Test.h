#pragma once
#include "stdafx.h"
#include "Loader.h"
#include <memory>

class TestDataFactory
{
private:
	Loader& m_loader;
	TestDataFactory& operator = (const TestDataFactory&); 
public:
	TestDataFactory(Loader& loader)
		:m_loader(loader)
	{

	}
	HCRYPTPROV CreateGoodHanle()
	{
		HCRYPTPROV phProv = NULL;
		CHAR pszContainer[] = "Test5";
		DWORD flag = 0;
		PVTableProvStruc pVTable = new VTableProvStruc();
		pVTable->pszProvName = "Test CSP";
		pVTable->dwProvType = 1;
		if(m_loader.AcquireContext(&phProv, pszContainer, flag, pVTable)!=TRUE)
			return NULL;
		return phProv;
	}

};

class Test
{
private:
	std::string m_name;
protected:
	Loader& m_loader;
	std::shared_ptr<TestDataFactory> m_factory;
	Test& operator = (Test&);
public:
	Test(const std::string& nameTest, Loader& loader)
		:m_name(nameTest), m_loader(loader)
	{
		m_factory = std::shared_ptr<TestDataFactory>(new TestDataFactory(loader));
	}
	
	virtual bool Execute() = 0;
	std::string GetName()
	{
		return m_name;
	}
};

class TestCPAcquireContext : public Test
{
private:
	TestCPAcquireContext& operator = (TestCPAcquireContext&);
public:
	bool Execute()
	{
	}
	TestCPAcquireContext(Loader& loader): 
	  Test("CPAcquireContext", loader)
	{
	}
};

class TestCPReleaseContext: public Test
{
private:
	TestCPReleaseContext& operator = (TestCPReleaseContext&);
public:
	TestCPReleaseContext(Loader& loader): 
	  Test("CPReleaseContext", loader)
	  {
		  ;
	  }
	bool Execute()
	{
		HCRYPTPROV phProv = m_factory->CreateGoodHanle();
		if(phProv==NULL)
			return false;
		
		if(m_loader.ReleaseContext(phProv, 0)!=TRUE)
			return false;
		return true;
	}
};

