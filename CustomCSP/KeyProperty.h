#include <Windows.h>
#include "CSPException.h"
#include "Key.h"
#include "Provider.h"
#include "ProviderInfo.h"
#include "CryptoFabric.h"
#include "Hash.h"

template<class T>
class KeyProperty
{
protected:
	T* m_key;
	DWORD m_param;
public: 
	KeyProperty(T* key):m_key(key), m_param(NULL)
	{
	}
	KeyProperty(T* key, DWORD param):m_key(key), m_param(param)
	{
	}
	virtual DWORD GetSize() = 0;
	virtual void GetProperty(BYTE* data, DWORD size)=0;
	virtual void SetProperty(BYTE* data) = 0;
};

//class ALGID : public KeyProperty<Key>
//{ 
//public: 
//	ALGID(Key *key): KeyProperty(key)
//	{
//	}
//	DWORD GetSize()
//	{
//		return sizeof(ALG_ID);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		ALG_ID alg = m_key->GetAlgId();
//		std::_Copy_impl((BYTE*)&alg, (BYTE*)&alg+GetSize(), &data[0]);
//	}
//	void SetProperty(BYTE* data)
//	{
//		throw ::NteNoSupported();
//	}
//};

//class BlockLen : public KeyProperty<Key>
//{
//public:
//	BlockLen(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		DWORD blockLen =0;
//		std::_Copy_impl(&data[0], &data[0]+GetSize(), (BYTE*)blockLen);
//		m_key->SetBlockLen(blockLen);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD blockLen = m_key->GetBlockLen();
//		std::_Copy_impl((BYTE*)&blockLen, (BYTE*)&blockLen+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

//class KeyLen : public KeyProperty<Key>
//{
//public:
//	KeyLen(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		throw ::NteNoSupported();
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD keyLen = m_key->GetKeyLen();
//		std::_Copy_impl((BYTE*)&keyLen, (BYTE*)&keyLen+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

//class Certificate: public KeyProperty<Key>
//{
//public:
//	Certificate(Key* key): KeyProperty(key)
//	{
//	}
//	void SetProperty(BYTE* data)
//	{
//		
//		//TODO: разбирать сертификат на корректность
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		std::vector<BYTE> cert;
//		m_key->GetCert(cert);
//		if(size<cert.size())
//			throw ::ErrorMoreData();
//
//		std::_Copy_impl(cert.begin(), cert.end(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		std::vector<BYTE> cert;
//		m_key->GetCert(cert);
//		return cert.size();
//	}
//};

//class SaltProperty : public KeyProperty<Key>
//{
//public:
//	SaltProperty(Key* key): KeyProperty(key)
//	{
//	}
//	void SetProperty(BYTE* data)
//	{
//		DWORD saltSize = GetSize();
//		
//		std::vector<BYTE> salt(saltSize);
//		std::_Copy_impl(&data[0], &data[0]+saltSize, salt.begin());
//		m_key->SetSalt(salt);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		std::vector<BYTE> salt;
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//		m_key->GetSalt(salt);
//		std::_Copy_impl(salt.begin(), salt.end(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return m_key->GetSaltSize();
//	}
//
//};

//class IVProperty : public KeyProperty<Key>
//{
//public:
//	IVProperty(Key* key): KeyProperty(key)
//	{
//	}
//	void SetProperty(BYTE* data)
//	{
//		DWORD ivSize = m_key->GetIVSize();
//		
//		std::vector<BYTE> iv(ivSize);
//		std::_Copy_impl(&data[0], &data[0]+ivSize, iv.begin());
//		m_key->SetIV(iv);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		std::vector<BYTE> iv;
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		m_key->GetIV(iv);
//		std::_Copy_impl(iv.begin(), iv.end(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return m_key->GetIVSize();
//	}
//
//};

//class Permissions : public KeyProperty<Key>
//{
//public:
//	Permissions(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		DWORD permissions =0;
//		std::_Copy_impl(&data[0], &data[0]+GetSize(), (BYTE*)permissions);
//		m_key->SetPermissions(permissions);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD permissions = m_key->GetPermissions();
//		std::_Copy_impl((BYTE*)&permissions, (BYTE*)&permissions+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

//class Padding : public KeyProperty<Key>
//{
//public:
//	Padding(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		DWORD padding =0;
//		std::_Copy_impl(&data[0], &data[0]+GetSize(), (BYTE*)padding);
//		m_key->SetPadding(padding);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD padding = m_key->GetPadding();
//		std::_Copy_impl((BYTE*)&padding, (BYTE*)&padding+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

//class Mode : public KeyProperty<Key>
//{
//public:
//	Mode(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		DWORD mode =0;
//		std::_Copy_impl(&data[0], &data[0]+GetSize(), (BYTE*)mode);
//		m_key->SetMode(mode);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD mode = m_key->GetMode();
//		std::_Copy_impl((BYTE*)&mode, (BYTE*)&mode+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

//class ModeBits : public KeyProperty<Key>
//{
//public:
//	ModeBits(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		DWORD modeBits =0;
//		std::_Copy_impl(&data[0], &data[0]+GetSize(), (BYTE*)modeBits);
//		m_key->SetModeBits(modeBits);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD modeBits = m_key->GetModeBits();
//		std::_Copy_impl((BYTE*)&modeBits, (BYTE*)&modeBits+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

//class EffectiveKeyLen : public KeyProperty<Key>
//{
//public:
//	EffectiveKeyLen(Key* key): KeyProperty(key){}
//	void SetProperty(BYTE* data)
//	{
//		DWORD effectiveKeyLen =0;
//		std::_Copy_impl(&data[0], &data[0]+GetSize(), (BYTE*)effectiveKeyLen);
//		m_key->SetEffectiveKeyLen(effectiveKeyLen);
//	}
//	void GetProperty(BYTE* data, DWORD size)
//	{
//		if(size<GetSize())
//			throw ::ErrorMoreData();
//
//		DWORD effectiveKeyLen = m_key->GetEffectiveKeyLen();
//		std::_Copy_impl((BYTE*)&effectiveKeyLen, (BYTE*)&effectiveKeyLen+GetSize(), &data[0]);
//	}
//	DWORD GetSize()
//	{
//		return sizeof(DWORD);
//	}
//};

KeyProperty<Key>* CreateKeyProperty(DWORD param, Key* key)
{
	UNREFERENCED_PARAMETER(param);
	UNREFERENCED_PARAMETER(key);
	throw ::ErrorInvalidParameter();
}

//KeyProperty<Key>* CreateKeyProperty(DWORD param, Key* key)
//{
//	switch(param)
//	{
//	case KP_ALGID: return new ALGID(key); break; 
//	case KP_BLOCKLEN: return new BlockLen(key); break;
//	case KP_CERTIFICATE:  return new Certificate(key); break;
//	case KP_KEYLEN: return new KeyLen(key); break;
//	case KP_SALT:  return new SaltProperty(key); break;
//	case KP_PERMISSIONS: return new Permissions(key); break;
//	case KP_IV: return new IVProperty(key); break;
//	case KP_PADDING: return new Padding(key); break;
//	case KP_MODE: return new Mode(key); break;
//	case KP_MODE_BITS: return new ModeBits(key); break;
//	case KP_EFFECTIVE_KEYLEN: return new EffectiveKeyLen(key); break;
//	}
//	
//	throw ::ErrorInvalidParameter();
//
//}
//

class ContainerProperty: public KeyProperty<Provider>
{
public:
	ContainerProperty(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		std::string name;
		m_key->GetContainerName(name);
		size_t len = name.size();
		if(size<len)
			throw ::ErrorMoreData();

		std::_Copy_impl(name.c_str(), name.c_str()+len, &data[0]);
	}
	DWORD GetSize()
	{
		std::string name;
		m_key->GetContainerName(name);
		return name.size();
	}
};

class Version : public KeyProperty<Provider>
{
public:
	Version(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();
		ProviderInfo info;
		(void)info; //BUG FIX warning C4101: 'info' : unreferenced local variable
		DWORD version = info.GetVersion();
		std::_Copy_impl((BYTE*)&version, (BYTE*)&version+GetSize(), &data[0]);
	}
	DWORD GetSize()
	{
		return sizeof(DWORD);
	}
};

class ProvType : public KeyProperty<Provider>
{
public:
	ProvType(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();

		DWORD type = m_key->GetType();
		std::_Copy_impl((BYTE*)&type, (BYTE*)&type+GetSize(), &data[0]);
	}
	DWORD GetSize()
	{
		return sizeof(DWORD);
	}
};

class ProvNameProperty: public KeyProperty<Provider>
{
public:
	ProvNameProperty(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		std::string name;
		m_key->GetName(name);
		size_t len = name.size();
		if(size<len)
			throw ::ErrorMoreData();

		std::_Copy_impl(name.c_str(), name.c_str()+len, &data[0]);
	}
	DWORD GetSize()
	{
		std::string name;
		m_key->GetName(name);
		return name.size();
	}
};

class ImplementationType : public KeyProperty<Provider>
{
public:
	ImplementationType(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();
		ProviderInfo info;
		(void)info;//BUG FIX warning C4101
		DWORD impl = info.GetImplementation();
		std::_Copy_impl((BYTE*)&impl, (BYTE*)&impl+GetSize(), &data[0]);
	}
	DWORD GetSize()
	{
		return sizeof(DWORD);
	}
};

class IncrementExchKeySize : public KeyProperty<Provider>
{
public:
	IncrementExchKeySize(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();

		ProviderInfo info;
		(void)info; //BUG FIX warning C4101
		ALG_ID algId = info.GetDefaultKeyXAlg();

		CryptoFactory factory;
		IAlg* pAlg = factory.CreateAlg(algId);

		if(pAlg==NULL)
			throw ::NteFail();

		std::shared_ptr<IAlg> alg = std::shared_ptr<IAlg>(pAlg);

		DWORD keyIncr = alg->GetIncrementKeySize();
		
		std::_Copy_impl((BYTE*)&keyIncr, (BYTE*)&keyIncr+GetSize(), &data[0]);
	}
	DWORD GetSize()
	{
		return sizeof(DWORD);
	}
};

class IncrementSignKeySize : public KeyProperty<Provider>
{
public:
	IncrementSignKeySize(Provider* prov): KeyProperty(prov){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}

	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();

		ProviderInfo info;
		(void)info; //BUG FIX warning C4101
		ALG_ID algId = info.GetDefaultSignAlg();

		CryptoFactory factory;
		IAlg* pAlg = factory.CreateAlg(algId);

		if(pAlg==NULL)
			throw ::NteFail();

		std::shared_ptr<IAlg> alg = std::shared_ptr<IAlg>(pAlg);

		DWORD keyIncr = alg->GetIncrementKeySize();

		std::_Copy_impl((BYTE*)&keyIncr, (BYTE*)&keyIncr+GetSize(), &data[0]);
	}
	DWORD GetSize()
	{
		return sizeof(DWORD);
	}
};

class EnumContainerProperty: public KeyProperty<Provider>
{
public:
	EnumContainerProperty(Provider* prov): KeyProperty(prov){}
	EnumContainerProperty(Provider* prov, DWORD param): KeyProperty(prov, param){}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}

	void GetProperty(BYTE* data, DWORD size)
	{
		std::string name;
		bool fistElement = m_param== CRYPT_FIRST;
		if(!m_key->EnumContainerName(name, false, fistElement))
			throw ::ErrorNoMoreItems();
		size_t len = name.size();
		if(size<len)
			throw ::ErrorMoreData();

		std::_Copy_impl(name.c_str(), name.c_str()+len, &data[0]);
	}
	DWORD GetSize()
	{
		std::string name;
		bool fistElement = m_param== CRYPT_FIRST;
		if(!m_key->EnumContainerName(name, true, fistElement))
			throw ErrorNoMoreItems();
		return name.size();
	}
};

KeyProperty<Provider>* CreateProvProperty(DWORD param, Provider* prov, DWORD flag)
{
	switch(param)
	{
	case PP_CONTAINER:return new ContainerProperty(prov);break;
	case PP_ENUMALGS: throw ::NteNoSupported(); break;
	case PP_ENUMALGS_EX: throw ::NteNoSupported(); break;
	case PP_ENUMCONTAINERS:return new EnumContainerProperty(prov, flag); break;
	case PP_IMPTYPE: return new ImplementationType(prov);break;
	case PP_KEYX_KEYSIZE_INC: return new IncrementExchKeySize(prov); break;
	case PP_NAME: return new ProvNameProperty(prov); break;
	case PP_PROVTYPE: return new ProvType(prov); break;
	case PP_SIG_KEYSIZE_INC: return new IncrementSignKeySize(prov); break;
	case PP_UNIQUE_CONTAINER: return new ContainerProperty(prov);break;
	case PP_VERSION: return new Version(prov);break;

	}
	throw ::NteBadType();
}

class HashSize : public KeyProperty<Hash>
{
	public: 
	HashSize(Hash *hash): KeyProperty(hash)
	{
	}
	DWORD GetSize()
	{
		return sizeof(m_key->GetHashSize());
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();

		DWORD hashSize = m_key->GetHashSize();
		std::_Copy_impl((BYTE*)&hashSize, (BYTE*)&hashSize+GetSize(), &data[0]);
	}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
};

class HashValue : public KeyProperty<Hash>
{
	public: 
	HashValue(Hash *hash): KeyProperty(hash)
	{
	}
	DWORD GetSize()
	{
		return m_key->GetHashSize();
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();

		m_key->GetHashValue(data, size);
	}
	void SetProperty(BYTE* data)
	{
		UNREFERENCED_PARAMETER(data);
		throw ::NteNoSupported();
	}
};

class HashId : public KeyProperty<Hash>
{ 
public: 
	HashId(Hash *hash): KeyProperty(hash)
	{
	}
	DWORD GetSize()
	{
		return sizeof(ALG_ID);
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		if(size<GetSize())
			throw ::ErrorMoreData();

		ALG_ID alg = m_key->GetId();
		std::_Copy_impl((BYTE*)&alg, (BYTE*)&alg+GetSize(), &data[0]);
	}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
};

class HmacInfo: public KeyProperty<Hash>
{
	public: 
	HmacInfo(Hash *hash): KeyProperty(hash)
	{
	}
	DWORD GetSize()
	{
		throw ::NteNoSupported();
		
	}
	void GetProperty(BYTE* data, DWORD size)
	{
		UNREFERENCED_PARAMETER(data);
		UNREFERENCED_PARAMETER(size);
		throw ::NteNoSupported();
	}
	void SetProperty(BYTE*)
	{
		throw ::NteNoSupported();
	}
};

KeyProperty<Hash>* CreateHashProperty(DWORD param, Hash* hash)
{
	switch(param)
	{
		case HP_HASHVAL:	return new HashValue(hash); break;
		case HP_HASHSIZE:	return new HashSize(hash); break;
		case HP_ALGID:		return new HashId(hash); break;
		case HP_HMAC_INFO:	return new HmacInfo(hash); break;
	}
	throw ::NteBadType();
}
