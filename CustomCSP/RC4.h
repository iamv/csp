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

//���������� ��������� RC4
class RC4 : public EncrAlg
{
private:
	//������������ �������� �����
	BYTE S[256];
	BYTE m_i;
	BYTE m_j;
	//������������� �����
	void KeyScheduling(std::vector<BYTE>& key);
protected:
	//��������� ���������� "����������" �����
	BYTE GetNext();
public:
	RC4(const RC4Key* key);
	virtual ~RC4();
	//���������� ������ �������������� ����� ����� ������� ���������
	void Encrypted(BYTE* input, DWORD* size, DWORD dataSize); //TODO: ������� ������������� ����������
	//������������ ������ �������������� ����� ����� ������� ���������
	void Decrypted(BYTE* input, DWORD* size);
	virtual Key* CreateKey(DWORD size, bool salt, bool exportable) const;
	virtual DWORD GetIncrementKeySize() const;
	virtual Key* ImportKey(const BYTE* blob, DWORD size) const;
};


//��������� ��������� ����� ���������� �� RC4 � ������ ��������
class PRNGRC4 : protected RC4
{
private:
	//�������� ������� ����������, �.�. ������� ��������� �� �����
	void Process(BYTE* input, BYTE* output, DWORD size);
public:
	PRNGRC4(RC4Key* key);
	//��������� "��������� ����"
	BYTE GetNextValue();
};


