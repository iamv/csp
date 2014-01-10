#include "stdafx.h"
#include "Provider.h"
#include "RC4.h"
#include "CryptoFabric.h"
#include "ProviderParamsCornverter.h"

std::string Provider::GetDefaultContainerName()
{
	return "DefaultKey.key";
}

Provider* Provider::CreateProvider(std::shared_ptr<ProviderParamsConverter> context, std::string& container)
{
	return new Provider(context, container);
}

void ReleaseProvider(Provider* prov)
{
	delete prov; 
}

Provider::~Provider()
{
	;
}

Provider::Provider(std::shared_ptr<ProviderParamsConverter> context, std::string& container): m_context(context), m_containerName(container)
{
	ProviderParamsConverter::ContainerOperation operation = m_context->GetOperation();
	if(m_containerName.empty() && operation!=ProviderParamsConverter::WithoutContainer)
		m_containerName = GetDefaultContainerName();
		
	m_keyStorage = std::shared_ptr<FileKeyStorage>(new FileKeyStorage);
	m_containerEnum = std::shared_ptr<ContNameEnumerator>(new ContNameEnumerator);
	m_algEnum = std::shared_ptr<AlgEnumerator>(new AlgEnumerator);
}

//container
void Provider::ExecuteContainerOperation()
{
	switch(m_context->GetOperation())
	{
	case ProviderParamsConverter::Create:			
	{
		std::string path = "D://";
		path.append(m_containerName);
		path.append(".key");
		
		if(!m_keyStorage->CreateKey(m_containerName,path)) 
			throw ::NteExists();
		break;						
	}
	case ProviderParamsConverter::Delete:
	{	
		if(!m_keyStorage->DeleteKey(m_containerName))
			throw ::NteKeySetNotDef();
		break;
	}
	case ProviderParamsConverter::Open:
	{
		if(!m_keyStorage->IsKeyExist(m_containerName))
			throw ::NteKeySetNotDef();
		break;
	}
	case ProviderParamsConverter::WithoutContainer:	
	{
		break;
	}
	default: 
			throw ::NteFail();
			break;
	}
}

//Container
void Provider::GetContainerName(std::string& name)
{
	name = m_containerName;
}
	
//Container
bool Provider::EnumContainerName(std::string& name, bool cashed, bool first )
{
	std::map<std::string, std::string> contList;
	m_keyStorage->EnumKey(contList);

	if(first)
		m_containerEnum->Reset();

	return m_containerEnum->Next(name, contList,cashed);
}

HashList& Provider::GetHashList()
{
	return m_HashList;
}

KeyList& Provider::KeyList()
{
	return m_KeyList;
}

//Hash
void Provider::HashKey(Hash* hash, const Key* key)
{
	UNREFERENCED_PARAMETER(hash); //TODO: написать
	key->Hashed();
}

//Hash
Hash* Provider::CreateHash(ALG_ID algId, const Key* key)
{
	return m_cryptoFactory.CreateHashAlg(algId, key);
}

//Sign
void Provider::CalculateSign(const Key* key, const Hash* hash, BYTE* sign, DWORD* signSize, DWORD dwFlags)
{
	UNREFERENCED_PARAMETER(dwFlags);
	ALG_ID algId = ProviderInfo::GetDefaultSignAlg();
	
	std::shared_ptr<SignAlg> alg = std::shared_ptr<SignAlg>(m_cryptoFactory.CreateSignAlg(algId));
	if(alg.get()==NULL)
		throw ::NteFail();

	alg->Sign(hash, key, sign, signSize); //TODO: флаги
}

//Sign
bool Provider::VerifySign(const Hash* hash,const Key* pubKey,const BYTE* sign, DWORD signSize, DWORD dwFlags)
{
	UNREFERENCED_PARAMETER(dwFlags);
	ALG_ID algId = ProviderInfo::GetDefaultSignAlg();
	
	std::shared_ptr<SignAlg> alg = std::shared_ptr<SignAlg>(m_cryptoFactory.CreateSignAlg(algId));
	if(alg.get()==NULL)
		throw ::NteFail();

	alg->Verify(hash, pubKey, sign, signSize); //TODO: флаги

	return true;
}

//Encrypted
void Provider::EncryptedBlock(const Key* key, BYTE* buffer, DWORD* bufferLen, DWORD dataLen, BOOL isFinal)
{
	ALG_ID algId = key->GetAlgId();
	std::shared_ptr<EncrAlg> alg = std::shared_ptr<EncrAlg>(m_cryptoFactory.CreateEncrAlg(algId, key));
	if(alg.get()==NULL)
		throw ::NteFail();

	alg->Encrypted(buffer, bufferLen, dataLen); 
	UNREFERENCED_PARAMETER(isFinal);
	throw NteNoSupported();
}

//Encrypted
void Provider::DecryptedBlock(const Key* key, BYTE* data, DWORD* size, BOOL isFinal)
{
	ALG_ID algId = key->GetAlgId();
	std::shared_ptr<EncrAlg> alg = std::shared_ptr<EncrAlg>(m_cryptoFactory.CreateEncrAlg(algId, key));
	if(alg.get()==NULL)
		throw ::NteFail();
	alg->Decrypted(data, size); 
	UNREFERENCED_PARAMETER(isFinal);
	throw NteNoSupported();
}

//Key
Key* Provider::DeriveKey(ALG_ID alg, DWORD keySize, const Hash* hash, bool exportable, bool salt)
{
	UNREFERENCED_PARAMETER(alg);
	UNREFERENCED_PARAMETER(keySize);
	UNREFERENCED_PARAMETER(hash);
	UNREFERENCED_PARAMETER(exportable);
	UNREFERENCED_PARAMETER(salt);
	throw NteNoSupported();
}

//Key
bool Provider::ExportKey(const Key* key,const Key* pubKey, DWORD blobType, std::vector<BYTE>& blob)
{
	BLOBHEADER blobHeader;
	blobHeader.aiKeyAlg = key->GetAlgId();
	blobHeader.bType = ((BYTE*)blobType)[3];
	blobHeader.bVersion = 2;
	blobHeader.reserved = 0;

	switch(blobType)
	{
		case SIMPLEBLOB:		
			{
				blobHeader.bType = SIMPLEBLOB; 
			}
			break;
		case PUBLICKEYBLOB:		blobHeader.bType = PUBLICKEYBLOB; break;
		case PRIVATEKEYBLOB:	blobHeader.bType = PRIVATEKEYBLOB; break;
		case PLAINTEXTKEYBLOB:	
			{
				blobHeader.bType = PLAINTEXTKEYBLOB;
				DWORD keyValueSize = 0;
				BYTE keyValueSizeBlob[sizeof(keyValueSize)];
				memcpy(&keyValueSizeBlob, &keyValueSize, sizeof(keyValueSize));
				std::reverse(&keyValueSizeBlob[0], &keyValueSizeBlob[0]+sizeof(keyValueSize));
				key->GetPlaitTextKey(NULL, &keyValueSize);
				std::vector<BYTE> keyValue(keyValueSize);
				key->GetPlaitTextKey(&keyValue[0], &keyValueSize);
				blob.resize(sizeof(blobHeader)+sizeof(keyValueSize)+keyValueSize);
				memcpy(&blob[0], &blobHeader, sizeof(blobHeader));
				memcpy(&blob[sizeof(blobHeader)], &keyValueSizeBlob, sizeof(keyValueSize));
				memcpy(&blob[sizeof(blobHeader)+sizeof(keyValueSize)], &keyValue, keyValueSize);
			}
			break;
		//PUBLICKEYBLOBEX
		//SYMMETRICWRAPKEYBLOB
		//OPAQUEKEYBLOB
		//KEYSTATEBLOB
		default: throw ::NteBadType(); break; 
	}
	UNREFERENCED_PARAMETER(pubKey);
	throw NteNoSupported(); //TODO: написать
}

//Key
Key* Provider::ImportKey(const BYTE* blob, DWORD size, Key* pubKey)
{
	BLOBHEADER blobHeader;
	if(size < sizeof(blobHeader) || blob==NULL)
		throw ::ErrorInvalidParameter();

	memcpy(&blobHeader, blob, sizeof(blobHeader));
	switch(blobHeader.bType)
	{
		case SIMPLEBLOB: break;
		case PUBLICKEYBLOB: break;
		case PRIVATEKEYBLOB: break;
		case PLAINTEXTKEYBLOB: 
			{
				std::unique_ptr<IAlg> alg(m_cryptoFactory.CreateAlg(blobHeader.aiKeyAlg));
				DWORD keyLen =0;
				BYTE tmpSize[sizeof(DWORD)];
				memcpy(&tmpSize, blob+sizeof(blobHeader), sizeof(DWORD));
				std::reverse(tmpSize, tmpSize+sizeof(DWORD));
				memcpy(&keyLen, tmpSize, sizeof(DWORD));
				if(size < (sizeof(blobHeader)+sizeof(DWORD)+keyLen))
					throw ::ErrorInvalidParameter();
				return alg->ImportKey(blob+sizeof(blobHeader)+sizeof(DWORD), keyLen);
			}
			break;	
		default: throw ::NteBadType(); break;
	}

	UNREFERENCED_PARAMETER(pubKey);
	throw NteNoSupported(); //TODO: написать
}

//Key
Key* Provider::GenTemporaryKey(ALG_ID id, DWORD keySize, bool salt, bool exportable)
{
	std::shared_ptr<IAlg> alg = std::shared_ptr<IAlg>(m_cryptoFactory.CreateAlg(id));
	
	if(alg.get()==NULL)
		throw ::NteFail();

	return alg->CreateKey(keySize, salt, exportable);
}

Key* Provider::GenPermanentKey(ALG_ID id, DWORD keySize, bool salt, bool exportable)
{
	ProviderInfo info;
	(void)info;
	ALG_ID idAlg = id == AT_SIGNATURE ? info.GetDefaultSignAlg() : info.GetDefaultKeyXAlg();
	
	std::shared_ptr<IAlg> alg = std::shared_ptr<IAlg>(m_cryptoFactory.CreateAlg(idAlg));
	Key* key = alg->CreateKey(keySize, salt, exportable);
	
	throw NteNoSupported(); //TODO: написать сохранеие в памяти
	return key;
}

//Key
Key* Provider::GetPermanentKey(bool signature)
{
	UNREFERENCED_PARAMETER(signature);
	throw NteNoSupported(); //TODO:
}

//Random
void Provider::GenRandom(BYTE* data, DWORD size)
{
		//TODO: переписать на фортуну
}


//extended info
void Provider::GetName(std::string& name)
{
	this->m_context->GetProvName(name);
}

//extended info
DWORD Provider::GetType()
{
	return this->m_context->GetProvType();
}
