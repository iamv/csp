#pragma once

#include "Key.h"
#include "Encrypted.h"
#include "RC4.h"
#include "CSPException.h"
#include "Alg.h"
#include "SignAlg.h"
#include "ExchAlg.h"

//������ ������ � �������� ������,
//�� �������� ������� ����� ���������, � ������� ���������� ��� ������ ��������, 
//�������� ����� � ���� � � ���, ��� ����������� ���� �����(�������� ��������� ������� ������)  
class CryptoFactory
{
public:
	IAlg* CreateAlg(ALG_ID id) const
	{
		switch(id)
		{
			default: throw ::NteBadAlgID(); 
				break;
		}
	}
	Hash* CreateHashAlg(ALG_ID id, const Key *key) const
	{
		UNREFERENCED_PARAMETER(key);
		switch(id)
		{
			default: throw ::NteBadAlgID(); 
				break;
		}
	}
	SignAlg* CreateSignAlg(ALG_ID id) const
	{
		switch(id)
		{
			default: throw ::NteBadAlgID(); 
				break;
		}
	}
	ExchAlg* CreateExchKeyAlg(ALG_ID id) const
	{
		switch(id)
		{
			default: throw ::NteBadAlgID(); 
				break;
		}
	}

	EncrAlg* CreateEncrAlg(ALG_ID id,const Key* key) const
	{
		switch(id)
		{
			case CALG_RC4: return new RC4((RC4Key*)key); break; //TODO: �����
			default: throw ::NteBadAlgID(); 
				break;
		}
	}
};

////����� ������� �������� ����������������� �������: ����, ������� ����������, �������
//class CryptoFabric
//{
//public:
//	static Key* CreateKey(ALG_ID id, DWORD keySize, bool isExportable, bool salt)
//	{
//		switch(id)
//		{
//			case CALG_RC4: return new RC4Key(isExportable); break;
//			default: throw ::NteBadAlgID(); break;
//		}
//	}
//
//	static EncryptedAlg* CreateEncryptedAlg(ALG_ID id, Key* key)
//	{
//		switch(id)
//		{
//			case CALG_RC4:
//			{
//				//��������� ���� �� �������������� ������ ��� RC4
//				RC4Key* rc4Key = dynamic_cast<RC4Key*>(key);
//				if(rc4Key==NULL)
//					throw ::NteBadKey();
//				return new EncryptedRC4(rc4Key);
//				break;
//			}
//			default: throw ::NteBadAlgID(); break;
//		}
//	}
//
//	static Hash* CreateHash(ALG_ID id, Key* key)
//	{
//		switch(id)
//		{
//			case CALG_MD5: return new HashMD5(); break;
//			default: throw ::NteBadAlgID(); break;
//		}
//	}
//
//	//TODO: ������� �������� �������
//	//TODO: ������� �������� ������ �������
//};