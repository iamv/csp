#include "stdafx.h"
#include <iostream>
#include "Buffer.h"

Buffer64::Buffer64()
{
	ptr_result = m_result;
	ptr_memory = m_memory;
	index = 0;
	m_sizeBuffer = 64;
	m_full =false;
}

Buffer64& Buffer64::operator = (const Buffer64& over)
{
	if(this == &over)
	{
        return *this;
	}
	m_sizeBuffer = over.m_sizeBuffer;
	for(DWORD i =0; i < m_sizeBuffer; ++i)
	{
		m_result[i]=over.m_result[i];
		m_memory[i]=over.m_memory[i];
	}

	ptr_result = m_result; //это может быть не правильным. ¬ообще этот класс
	ptr_memory = m_memory;
	
	index = over.index;
	m_full = over.m_full;

	return *this;
}

DWORD Buffer64::GetValue(BYTE* outBuffer)
{
	
	DWORD size = m_full ? m_sizeBuffer : index;
	for(DWORD i=0; i < size; ++i)
		outBuffer[i] = ptr_result[i];
	return size;
}
DWORD Buffer64::SetValue(BYTE* buffer, DWORD size)
{
if(m_full)
	{
		std::swap(ptr_result, ptr_memory);
		for(DWORD i=0;i<m_sizeBuffer;++i)
			ptr_memory[i]=0;
	};
	m_full = false;
	DWORD freeSize = m_sizeBuffer - index;
	DWORD copySize = std::min<DWORD>(freeSize, size);
	for(DWORD i=0; i<copySize; ++i, ++index)
		ptr_result[index] = buffer[i];
		
	if(index!=m_sizeBuffer)
		return copySize;
	index = 0;
	m_full=true;
	DWORD overloadSize = size-copySize;
	for(DWORD i=0;i<overloadSize;++i, ++index)
		ptr_memory[i]=buffer[i+copySize];
	return copySize+overloadSize;
}

DWORD Buffer64::GetIndex()
{
	return index;
}