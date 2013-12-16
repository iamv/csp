#pragma once
#include <Windows.h>
#include <set>
#include <map>
#include <iostream>
#include <string>

class AlgEnumerator
{
};

class ContNameEnumerator
{	
private:
	std::set<std::string> m_list;
	std::string m_cash;
public:
	ContNameEnumerator():
	  m_cash("")
	{
		
	}
	void Reset()
	{
		m_list.clear();
	}
	
	bool Next(std::string& value, std::map<std::string, std::string> src, bool cashedValue = false)
	{
		//TODO: здесь может быть возвращено некорректное значение, 
		//если сначала получили размер имени следующего контейнера, т.е. запомнили значение
		//а потом удалили этот контейнер
		if(!m_cash.empty())
		{
			value = m_cash;
			return true;
		}

		std::map<std::string, std::string>::iterator i = src.begin();
		for(;i!=src.end();++i)
		{
			if(m_list.find((*i).first)==m_list.end())
			{
				if(cashedValue)
				{
					m_cash = (*i).first;	
					value = m_cash;
					return true;
				}
				
				value = (*i).first;
				m_list.insert(m_list.end(), value);
				m_cash = "";
				return true;
			}
		}
		return false;
	}
	bool NextSize(DWORD& size, std::map<std::string, std::string> src)
	{
		std::map<std::string, std::string>::iterator i = src.begin();
		for(;i!=src.end();++i)
		{
			if(m_list.find((*i).first)==m_list.end())
			{
				size = (*i).first.size();
				return true;
			}
		}
		return false;
	}
};