#pragma once
#include "Hash.h"
#include "Buffer.h"

class HashMD5 : public Hash
{
public:
	HashMD5();
	virtual HashMD5* Clone() const;
	virtual bool IsFinished() const;
	virtual void AddData(const BYTE *pbData, DWORD cbDataLen);
	virtual void SetValue(const BYTE* data);
	virtual bool GetHashValue(BYTE* hashVal, DWORD hashValSize);
	virtual DWORD GetHashSize() const;
	virtual void ReOpen();

private:
	bool m_isFinished;
	DWORD m_hashSize;
	std::shared_ptr<Buffer> m_buffer;
	std::vector<DWORD> m_state;
	virtual Key* CreateKey(DWORD size, bool salt, bool exportable) const;
	virtual DWORD GetIncrementKeySize() const;
	virtual void Update(std::vector<BYTE>&data);
	virtual void Finished(std::vector<BYTE>& result);
	static unsigned long F(unsigned long x, unsigned long y, unsigned long z);
	static unsigned long G(unsigned long x, unsigned long y, unsigned long z);
	static unsigned long H(unsigned long x, unsigned long y, unsigned long z);
	static unsigned long I(unsigned long x, unsigned long y, unsigned long z);
	static unsigned long RotateLeft(unsigned long x, unsigned long n);
	unsigned long R(unsigned long a, unsigned long b, unsigned long c, unsigned long d, unsigned long x, unsigned long s, unsigned long int ac, unsigned long (*func)(unsigned long x, unsigned long y, unsigned long z));
	void Round(unsigned char* block);
	void Decode (DWORD *output, BYTE *input, DWORD len);
	void Encode(BYTE* Output, DWORD* Input, DWORD nLength);
	virtual Key* ImportKey(const BYTE* blob, DWORD size) const;
};