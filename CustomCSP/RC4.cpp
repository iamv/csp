#include "stdafx.h"
#include <iostream>
#include "RC4.h"
#include "HashMD5.h"
#include "Encrypted.h"

class RC4Key;
Key* RC4::CreateKey(DWORD size, bool salt, bool exportable) const
{
	UNREFERENCED_PARAMETER(size);
	UNREFERENCED_PARAMETER(salt);
	//TODO: salt, size
	return new RC4Key(exportable); 
}
Key* RC4::ImportKey(const BYTE* blob, DWORD size) const
{
	return new RC4Key(blob, size);
}

DWORD RC4::GetIncrementKeySize() const
{
	return 0;
}

void RC4::KeyScheduling(std::vector<BYTE>& key)
{
	for(BYTE i = 0; i<256; ++i)
		S[i] = i;
		
	int j = 0;
	for(int i=0; i<256; ++i)
	{
		j = (j + S[i] + key[i % key.size()]) % 256;
		std::swap(S[i],S[j]);
	}
}
BYTE RC4::GetNext()
{
	m_i = (m_i+1) % 256;
	m_j = (m_j+S[m_j]) % 256;
	std::swap(m_i, m_j);
	BYTE result = S[(S[m_i]+S[m_j]) % 256];
	return result;
}


RC4::RC4(const RC4Key* key) : EncrAlg(CALG_RC4, 256, 256, 256, 0x0007, L"RC4", L"RC4")
{
	std::vector<BYTE> valKey; //TODO: а если ключ NULL
	key->GetValue(valKey);
	KeyScheduling(valKey);
}

void RC4::Decrypted(BYTE* input, DWORD* size)
{
	DWORD dataSize = *size;
	Encrypted(input, size, dataSize);
}
void RC4::Encrypted(BYTE* input, DWORD* size, DWORD dataSize)
{
	DWORD cashSize = *size;
	*size = dataSize;
	
	if(input==NULL)
		return;

	if(cashSize < dataSize)
		throw ::ErrorMoreData();
	
	//шифрование алгоритмом rc4 заключается в xor очередного значения счетчика и исходных данных 
	for(DWORD i =0; i < dataSize; ++i)
	{
		BYTE k = GetNext();
		input[i] = input[i]^k;
	}
}

BYTE PRNGRC4::GetNextValue()
{
	return GetNext();
}

PRNGRC4::PRNGRC4(RC4Key* key) : RC4(key)
{

}
RC4Key::RC4Key(bool isExport)
{
	m_algId = CALG_RC4;
	m_exportable = isExport;
	DWORD size = 16;
	(void)size; //BUG FIX in VS2010 'size' : local variable is initialized but not referenced
	m_value.resize(16);
	DWORD time = timeGetTime();
	HashMD5 hash;
	hash.AddData((BYTE*)&time, sizeof(time));
	std::vector<BYTE> hashVal(hash.GetHashSize());
	hash.GetHashValue(&hashVal[0], hashVal.size());
	std::_Copy_impl(hashVal.begin(), hashVal.end(), m_value.begin());		
}
RC4Key::RC4Key(const BYTE* value, DWORD len, bool isExport)
{
	m_algId = CALG_RC4;
	m_exportable = isExport;
	m_value.resize(len);
	std::_Copy_impl(&value[0], &value[0]+len, m_value.begin()); 
}
void RC4Key::GetValue(std::vector<BYTE>&value) const
{
	value.resize(m_value.size());
	std::_Copy_impl(m_value.begin(), m_value.end(), value.begin()); 
}
ALG_ID RC4Key::GetAlgId() const
{
	return m_algId;
}
RC4Key::~RC4Key()
{
}
RC4::~RC4()
{
}
void RC4Key::Hashed(void) const
{
	//TODO: реализовать
}

DWORD RC4Key::GetKeyLen() const
{
	return m_value.size();
}
void RC4Key::GetPlaitTextKey(BYTE* blob, DWORD* size) const
{
	DWORD cashedSize = *size;
	DWORD keySize = GetKeyLen();
	*size = keySize;
	if(blob==0)
		return;
	if(cashedSize < keySize)
		throw ::ErrorMoreData(); //TODO: не хорошо т.к. это исключение кидается в вызфвающей функции
	memcpy(blob, &m_value[0], keySize);
}
DWORD RC4Key::GetBlockLen() const
{
	return m_blockLen;
}

DWORD RC4Key::GetEffectiveKeyLen() const
{
	return this->m_effectiveKeyLen;
}

DWORD RC4Key::GetIVSize() const
{
	return m_IV.size();
}

DWORD RC4Key::GetMode() const
{
	return m_mode;
}

DWORD RC4Key::GetModeBits() const
{
	return this->m_modeBits;
}

void RC4Key::GetIV(std::vector<BYTE>& iv) const
{
	iv.resize(GetIVSize());
	std::copy(m_IV.begin(), m_IV.end(), iv.begin());
}

void RC4Key::GetSalt(std::vector<BYTE>& salt) const
{
	salt.resize(GetSaltSize());
	std::copy(m_salt.begin(), m_salt.end(), salt.begin());
}

DWORD RC4Key::GetSize() const
{
	return m_value.size();
}

DWORD RC4Key::GetPermissions() const
{
	throw ::NteNoSupported();
}
DWORD RC4Key::GetSaltSize() const
{
	return m_salt.size();
}
void RC4Key::GetCert(std::vector<BYTE>& cert) const
{
	cert.resize(GetCertSize());
	std::copy(m_cert.begin(), m_cert.end(), cert.begin());
}

DWORD RC4Key::GetCertSize() const
{
	return m_cert.size();
}

DWORD RC4Key::GetPadding() const
{
	return m_padding;
}

void RC4Key::SetBlockLen(DWORD blockLen)
{
	m_blockLen = blockLen;
}

void RC4Key::SetCert(std::vector<BYTE>& cert)
{
	m_cert.resize(cert.size());
	std::_Copy_impl(cert.begin(), cert.end(), m_cert.begin());
}

void RC4Key::SetEffectiveKeyLen(DWORD len)
{
	m_effectiveKeyLen = len;
}

void RC4Key::SetIV(std::vector<BYTE>& iv)
{
	m_IV.resize(iv.size());
	std::_Copy_impl(iv.begin(), iv.end(), m_IV.begin());
}
void RC4Key::SetSalt(std::vector<BYTE>& salt)
{
	m_salt.resize(salt.size());
	std::_Copy_impl(salt.begin(),salt.end(), m_salt.begin());
}

void RC4Key::SetMode(DWORD mode)
{
	m_mode = mode;
}

void RC4Key::SetModeBits(DWORD modeBits)
{
	m_modeBits = modeBits;
}

void RC4Key::SetPadding(DWORD padding)
{
	m_padding=padding;
}

void RC4Key::SetPermissions(DWORD permissions)
{
	UNREFERENCED_PARAMETER(permissions);
	//TODO:
}

RC4Key* RC4Key::Clone() const
{
	return new RC4Key();
}