#pragma once
#include <Windows.h>
#include <vector>
#include "Key.h"
#include "Encrypted.h"

class RC4Key : public Key
{
private:
	ALG_ID m_algId;
	bool m_exportable;
	std::vector<BYTE> m_value;
	std::vector<BYTE> m_cert;
	std::vector<BYTE> m_IV;
	std::vector<BYTE> m_salt;
	DWORD m_blockLen;
	DWORD m_padding;
	DWORD m_mode;
	DWORD m_modeBits;
	DWORD m_effectiveKeyLen;
public:
	RC4Key(bool isExport=false);
	virtual ~RC4Key();
	RC4Key(const BYTE* value, DWORD len, bool isExport=false);
	void GetValue(std::vector<BYTE>&value) const;
	DWORD GetKeyLen() const;
	DWORD GetCertSize() const;
	void GetCert(std::vector<BYTE>& cert) const;
	DWORD GetSaltSize() const;
	void GetSalt(std::vector<BYTE>& salt) const;
	DWORD GetBlockLen() const;
	DWORD GetPadding() const;
	DWORD GetMode() const;
	DWORD GetModeBits() const;
	DWORD GetEffectiveKeyLen() const;
	DWORD GetIVSize() const;
	void GetIV(std::vector<BYTE>& iv) const;
	void SetBlockLen(DWORD blockLen);
	void SetCert(std::vector<BYTE>& cert);
	void SetSalt(std::vector<BYTE>& salt);
	void SetPermissions(DWORD permissions);
	void SetPadding(DWORD padding);
	void SetMode(DWORD mode);
	void SetModeBits(DWORD modeBitd);
	void SetEffectiveKeyLen(DWORD keyLen);
	void SetIV(std::vector<BYTE>& iv);
	RC4Key* Clone() const;
	DWORD GetPermissions() const;
	DWORD GetSize() const;
	virtual void Hashed(void) const;
	virtual ALG_ID GetAlgId() const;
	virtual void GetPlaitTextKey(BYTE* blob, DWORD* size) const;
};

//реализпция алгоритма RC4
class RC4 : public EncrAlg
{
private:
	//перемешанное значение ключа
	BYTE S[256];
	BYTE m_i;
	BYTE m_j;
	//перемешивание ключа
	void KeyScheduling(std::vector<BYTE>& key);
protected:
	//получение следующего "случайного" байта
	BYTE GetNext();
public:
	RC4(const RC4Key* key);
	virtual ~RC4();
	//шифрование размер зашифрованного блока равен размеру открытого
	void Encrypted(BYTE* input, DWORD* size, DWORD dataSize); //TODO: хранить промежуточные результаты
	//дешифрование размер зашифрованного блока равен размеру открытого
	void Decrypted(BYTE* input, DWORD* size);
	virtual Key* CreateKey(DWORD size, bool salt, bool exportable) const;
	virtual DWORD GetIncrementKeySize() const;
	virtual Key* ImportKey(const BYTE* blob, DWORD size) const;
};


//генератор случайных чисел основанный на RC4 в режиме счетчика
class PRNGRC4 : protected RC4
{
private:
	//скрываем функцию шифрования, т.к. счетчик шифровать не может
	void Process(BYTE* input, BYTE* output, DWORD size);
public:
	PRNGRC4(RC4Key* key);
	//следующий "случайный байт"
	BYTE GetNextValue();
};


