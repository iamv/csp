#pragma once
#include<vector>
#include <list>
#include<algorithm>
template<class Element, class ListElements = std::list<Element>, class ListIterator = std::list<Element>::iterator>
class Storage
{
private: 
	ListElements _list;
public:
	typedef ListIterator Iterator;
	Iterator end()
	{
		return _list.end();
	}
	Iterator find(Element findElement)
	{
		return std::find(_list.begin(), _list.end(), findElement);
	}
	void add(Element element)
	{
		_list.push_back(element);
	}
	bool remove(Element element)
	{
		ListElements::iterator pos = find(element);
		if(pos==_list.end())
			return false;
		 _list.erase(pos);
		return true;
	}
};

