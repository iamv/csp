#pragma once
#include <Windows.h>
class Buffer
{
public:
	virtual DWORD GetValue(BYTE* outBuffer)=0;
	virtual DWORD SetValue(BYTE* buffer, DWORD size)=0;
	virtual DWORD GetIndex()=0;
};
class Buffer64: public Buffer
	{
	private:
		BYTE m_result[64];
		BYTE m_memory[64];
		BYTE* ptr_result;
		BYTE* ptr_memory;
		DWORD m_sizeBuffer;
		DWORD index;
		bool m_full;
	public:
		Buffer64();
		DWORD GetValue(BYTE* outBuffer);
		DWORD SetValue(BYTE* buffer, DWORD size);
		DWORD GetIndex();
		Buffer64& operator = (const Buffer64& over);
	};