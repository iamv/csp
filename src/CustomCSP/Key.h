#pragma once

#include <Windows.h>
#include <vector>
#include "CSPException.h"

class Key
{
public:
	Key()
	{
	}
	virtual ~Key()
	{
	}
	/*Property* CreateProperty(DWORD param) const
	{
		return NULL;
	}*/
	virtual void Hashed() const =0;
	virtual Key* Clone() const =0;
	virtual ALG_ID GetAlgId() const =0;
	virtual void GetPlaitTextKey(BYTE* blob, DWORD* size) const = 0;
};

//class Key
//{
//public:
//	virtual DWORD GetCertSize() const =0;
//	virtual DWORD GetSaltSize() const =0;
//	virtual ALG_ID GetAlgId()const  =0;
//	virtual DWORD GetBlockLen() const =0;
//	virtual void SetBlockLen(DWORD blockLen) =0;
//	virtual void GetCert(std::vector<BYTE>& cert) const =0;
//	virtual void SetCert(std::vector<BYTE>& cert) =0;
//	virtual DWORD GetKeyLen() const =0;
//	virtual void GetSalt(std::vector<BYTE>& salt) const =0;
//	virtual void SetSalt(std::vector<BYTE>& salt)  =0;
//	virtual DWORD GetPermissions() const  =0;
//	virtual void SetPermissions(DWORD permissions)  =0;
//	virtual DWORD GetPadding() const  =0;
//	virtual void SetPadding(DWORD padding) =0;
//	virtual DWORD GetMode() const =0;
//	virtual void SetMode(DWORD mode)=0;
//	virtual DWORD GetModeBits() const=0;
//	virtual void SetModeBits(DWORD modeBitd)=0;
//	virtual DWORD GetEffectiveKeyLen() const=0;
//	virtual void SetEffectiveKeyLen(DWORD keyLen)=0;
//	virtual void GetIV(std::vector<BYTE>& iv) const=0;
//	virtual void SetIV(std::vector<BYTE>& iv)=0;
//	virtual DWORD GetIVSize() const=0; 
//	virtual DWORD GetSize() const=0;
//	virtual void GetValue(std::vector<BYTE>& data) const=0;
//	virtual Key* Clone() const=0;
//};
