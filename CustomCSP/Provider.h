#pragma once
#include <iostream>
#include <Windows.h>
#include <WinCrypt.h>

#include "common.h"

#include "Storage.h"
#include "FileKeyStorage.h"

#include "CryptoFabric.h"

//#include "Key.h"
#include "Blob.h"
#include "Enumerator.h"
#include "ProviderParamsCornverter.h"
#include "ProviderInfo.h"

class Provider;

typedef Storage<Hash*> HashList;
typedef Storage<Key*> KeyList;
typedef Storage<Provider*> ProvStorage;

class Provider
{
private:
	CryptoFactory m_cryptoFactory;

	//public key for exchange key
	std::shared_ptr<Key> exchPubKey;
	
	//private key for exchange key
	std::shared_ptr<Key> exchPrivKey;
	
	//public key for signature 
	std::shared_ptr<Key> sigPubKey;
	
	//private key for signature
	std::shared_ptr<Key> sigPrivKey;
	
	//key storage
	std::shared_ptr<FileKeyStorage> m_keyStorage;
	
	//enumerator key containers
	std::shared_ptr<ContNameEnumerator> m_containerEnum;
	
	//enumerator algs
	std::shared_ptr<AlgEnumerator> m_algEnum;
	
	//List for temporarily stored hash
	HashList m_HashList;
	
	//List for temporarily stored key
	KeyList m_KeyList;
	
	//Current state of provider
	std::shared_ptr<ProviderParamsConverter> m_context;
	
	//Name of Current container 
	std::string m_containerName;
public:
	static Provider* CreateProvider(std::shared_ptr<ProviderParamsConverter> context, std::string& container);
	static void ReleaseProvider(Provider*);
	Provider(std::shared_ptr<ProviderParamsConverter> context, std::string& container);
	virtual ~Provider();
	
	//container
	void ExecuteContainerOperation();
	void GetContainerName(std::string& name);
	bool EnumContainerName(std::string& name, bool cashed = false, bool first = false);
	std::string GetDefaultContainerName();

	//store
	HashList& GetHashList();
	KeyList& KeyList();
	
	//hash
	void HashKey(Hash* hash, const Key* key);
	Hash* CreateHash(ALG_ID algId, const Key* key);
	
	//sign
	void CalculateSign(const Key* key, const Hash* hash, BYTE* sign, DWORD* signSize, DWORD dwFlags);
	bool VerifySign(const Hash* hash, const Key* pubKey, const BYTE* sign, DWORD signSize, DWORD dwFlags);
	
	//encrypted
	void EncryptedBlock(const Key* key, BYTE* buffer, DWORD* bufferLen, DWORD dataLen, BOOL isFinal);
	void DecryptedBlock(const Key* key, BYTE* data, DWORD* size, BOOL isFinal);
	
	//key
	Key* DeriveKey(ALG_ID alg, DWORD keySize, const Hash* hash, bool exportable = false,bool salt = false);
	bool ExportKey(const Key* key, const Key* pubKey, DWORD blobType, std::vector<BYTE>& blob);
	Key* ImportKey(const BYTE* blob, DWORD size, Key* pubKey);
	Key* GenTemporaryKey(ALG_ID id, DWORD keySize, bool salt, bool exportable);
	Key* GenPermanentKey(ALG_ID id, DWORD keySize, bool salt, bool exportable);
	Key* GetPermanentKey(bool signature);

	//random
	void GenRandom(BYTE* data, DWORD size);
	
	//info
	void GetName(std::string& name);
	DWORD GetType();
};