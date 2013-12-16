#include "stdafx.h"
#include "csp.h"
#include "CSPException.h"
#include "KeyProperty.h"
#include "Provider.h"

ProvStorage m_ProvStorage;
//This function acquires a handle to the key container specified by the pszContainer parameter
BOOL CPAcquireContext(HCRYPTPROV* phProv, CHAR* pszContainer, DWORD dwFlags, PVTableProvStruc pVTable)
{
	try
	{
		std::string containerName = "";
		
		//Set container name
		if(pszContainer!=NULL)
		{
			size_t containerLen = strlen(pszContainer);
			if(containerLen==0)
				throw ::ErrorInvalidParameter();
			if(containerLen>MAX_PATH)
				throw ::ErrorInvalidParameter();
			containerName = pszContainer;
		}
		
		//Create params of csp
		ProviderParamsConverter* context_ptr = new ProviderParamsConverter(dwFlags, pVTable);
		std::shared_ptr<ProviderParamsConverter> context(context_ptr);

		//Get operation with container
		ProviderParamsConverter::ContainerOperation operation = context->GetOperation(); 
		
		//If provider have not access to container,then name container is empty
		if(operation==ProviderParamsConverter::WithoutContainer)
			containerName = "";
		
		//Exucute operation on container
		std::unique_ptr<Provider> prov(Provider::CreateProvider(context, containerName));
		prov->ExecuteContainerOperation();
		
		//If operation on container is delete, then phProv (handle to provider) not created
		if(operation==ProviderParamsConverter::Delete)
			return TRUE;

		//Save phProv (handle to provider) to csp's list
		m_ProvStorage.add(prov.get());
		*phProv = (HCRYPTPROV)prov.get();
		prov.release();
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function retrieves parameters that govern the operations of a csp
BOOL CPGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen,DWORD dwFlags)
{
	try
	{
		//Only these flags (CRYPT_FIRST, CRYPT_MACHINE_KEYSET) are supported
		if(dwFlags!=NULL && dwFlags!=CRYPT_FIRST && dwFlags!=CRYPT_MACHINE_KEYSET)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get property of csp
		std::shared_ptr<KeyProperty<Provider>> prop(CreateProvProperty(dwParam,*prov, dwFlags)); 
		
		//Copy property value to buffer pbData
		if(pbData!=NULL)
			prop->GetProperty(pbData, *pdwDataLen);
		
		//Copy property size to pdwDataLen
		*pdwDataLen = prop->GetSize();

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function frees the handle to a csp
BOOL CPReleaseContext(HCRYPTPROV hProv, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Delete csp handle from csp's list
		std::unique_ptr<Provider> provHandle(*prov);
		m_ProvStorage.remove(*prov);
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function customizes the operations of a csp
BOOL CPSetProvParam(HCRYPTPROV hProv, DWORD dwParam, BYTE* pbData, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get property of csp
		std::shared_ptr<KeyProperty<Provider>> prop(CreateProvProperty(dwParam,*prov, dwFlags)); 

		//Set property value
		prop->SetProperty(pbData);

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function generates cryptographic session keys derived from base data
BOOL CPDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey)
{
	try
	{
		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get hash's list
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hBaseData);
		if(hash==hashList.end())
			throw NteBadHash();

		//Parsed key param from dwFlag
		bool exportable = (dwFlags&CRYPT_EXPORTABLE)==CRYPT_EXPORTABLE;
		dwFlags = dwFlags&~CRYPT_EXPORTABLE;
		bool salt = (dwFlags&CRYPT_CREATE_SALT)==CRYPT_CREATE_SALT;
		dwFlags = dwFlags&~CRYPT_CREATE_SALT;
		bool noSalt = (dwFlags&CRYPT_NO_SALT)==CRYPT_NO_SALT;
		dwFlags = dwFlags&~CRYPT_NO_SALT;
		DWORD keySize = dwFlags>>16;
		dwFlags = dwFlags&~0xFFFF0000;
		
		//If after parsing key param is not empty, this is undefinded flag
		if(dwFlags!=0)
			throw ::NteBadFlags();
		
		//This flag is incorrect
		if(salt==true && noSalt==true)
			throw ::NteBadFlags();
		
		//Generates key
		std::unique_ptr<Key> key((*prov)->DeriveKey(Algid, keySize, *hash, exportable, salt));
		
		//Save handle to key 
		KeyList& keyList= (*prov)->KeyList();
		keyList.add(key.get());		
		
		//Return the handle referenced by the key
		*phKey = (HCRYPTKEY)key.get();
		key.release();
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function frees the handle referenced by the hKey parameter. 
BOOL CPDestroyKey(HCRYPTPROV hProv, HCRYPTKEY hKey)
{
	try
	{
		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw NteBadKey();
		
		//Delete handle refers by key.
		//Key data deleted, if key was session or importing
		std::shared_ptr<Key> removeKey(*key);  
		keyList.remove(*key);
		hKey = NULL;
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function makes an exact copy of a key and the state the key is in
BOOL CPDuplicateKey(HCRYPTPROV hUID, HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey)
{
	try
	{
		//No parametrs supported
		if(pdwReserved!=NULL)
			throw ::ErrorInvalidParameter();

		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hUID);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw NteBadKey();

		//Clones kes
		std::unique_ptr<Key> copyKey((*key)->Clone());

		//Save new handle by key
		keyList.add(copyKey.get());

		//Return handle by key
		*phKey = (HCRYPTKEY)copyKey.get();
		copyKey.release();
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function exports cryptographic keys from of a csp
BOOL CPExportKey(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get handle to the key to be exported
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw NteBadKey();

		//Get handle to a key belonging to the destination user
		KeyList::Iterator keyPub = keyList.find((Key*)hPubKey);
		if(keyPub==keyList.end())
			throw NteBadKey();

		//Export key to blob
		std::vector<BYTE> blob;
		if(!(*prov)->ExportKey(*key, *keyPub, dwBlobType, blob))
			throw NteBadKeyState();

		//Save size of blob
		*pdwDataLen = blob.size();
		
		//If buffer is null, then return only size of blob 
		if(pbData==NULL)
			return TRUE;

		//Check buffer size
		if(*pdwDataLen<blob.size())
			throw ::ErrorMoreData();
		
		//Copy blob to buffer
		std::_Copy_impl(blob.begin(), blob.end(), &pbData[0]);
		return TRUE;
		
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function generates a random cryptographic session key or a public/private key pair for use with the csp
BOOL CPGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey)
{
	try
	{
		//Parsing param of key
		bool exportable = (dwFlags&CRYPT_EXPORTABLE)==CRYPT_EXPORTABLE;
		dwFlags = dwFlags&~CRYPT_EXPORTABLE;
		bool salt = (dwFlags&CRYPT_CREATE_SALT)==CRYPT_CREATE_SALT;
		dwFlags = dwFlags&~CRYPT_CREATE_SALT;
		bool noSalt = (dwFlags&CRYPT_NO_SALT)==CRYPT_NO_SALT;
		dwFlags = dwFlags&~CRYPT_NO_SALT;
		DWORD keySize = dwFlags>>16;
		dwFlags = dwFlags&~0xFFFF0000;
		if(dwFlags!=0)
			throw ::NteBadFlags();
		if(salt==true && noSalt==true)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();
		
		//Generate the key

		bool isPermanent = (Algid == AT_KEYEXCHANGE || Algid == AT_SIGNATURE); 

		std::unique_ptr<Key> key(isPermanent ? (*prov)->GenPermanentKey(Algid, keySize, salt, exportable) : (*prov)->GenTemporaryKey(Algid, keySize, salt, exportable));
		
		//Save handle by key
		KeyList& keyList = (*prov)->KeyList();
		keyList.add(key.get());

		//Return handle by key
		*phKey = (HCRYPTKEY)key.get();
		key.release();

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function fills a buffer with random bytes
BOOL CPGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer)
{
	try
	{
		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get rundom bitts
		(*prov)->GenRandom(pbBuffer, dwLen);

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function lets applications retrieve data that governs the operations of a key.
BOOL CPGetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);

		//Get property
		std::shared_ptr<KeyProperty<Key>> prop = std::shared_ptr<KeyProperty<Key>>(CreateKeyProperty(dwParam,*key)); 
		
		//Get property value
		if(pbData!=NULL)
			(*prop).GetProperty(pbData, *pdwDataLen);
		
		//Set propery value size
		*pdwDataLen = (*prop).GetSize();

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function retrieves a handle to a permanent user key pair, such as the user's signature key pair.
BOOL CPGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY* phUserKey)
{
	try
	{
		if(dwKeySpec!=AT_KEYEXCHANGE && dwKeySpec!=AT_SIGNATURE)
			throw ::NteBadKey();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		std::unique_ptr<Key> key((*prov)->GetPermanentKey(dwKeySpec==AT_SIGNATURE));

		//Save key to storage
		keyList.add(key.get());

		//Return key
		*phUserKey = (HCRYPTKEY)key.get();
		key.release();

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function transfers a cryptographic key from a key binary large object (BLOB) to the csp
BOOL CPImportKey(HCRYPTPROV hProv,const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.end();
		if(hPubKey!=NULL)
		{
			KeyList::Iterator key = keyList.find((Key*)hPubKey);
			if(key==keyList.end())
				throw NteBadKey();
		}

		//Import key
		std::unique_ptr<Key> newKey((*prov)->ImportKey(pbData, dwDataLen, key == keyList.end() ? NULL : *key));
		
		//Save importing key
		keyList.add(newKey.get());

		//Return importing key
		*phKey = (HCRYPTKEY)newKey.get(); 
		newKey.release();
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function customizes various aspects of a key's operations.
BOOL CPSetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw NteBadKey();

		//Get property
		std::shared_ptr<KeyProperty<Key>> prop = std::shared_ptr<KeyProperty<Key>>(CreateKeyProperty(dwParam,*key)); 
		
		//Set Property
		(*prop).SetProperty(pbData);

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function decrypts data that was previously encrypted with the CryptEncrypt function
BOOL CPDecrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw ::NteBadKey();

		(*prov)->DecryptedBlock(*key, pbData, pdwDataLen, Final);
		
		if(hHash!=NULL && pbData!=NULL)
		{
			//Get hash object
			HashList& hashList = (*prov)->GetHashList();
			HashList::Iterator hash = hashList.find((Hash*)hHash);
			if(hash==hashList.end())
				throw NteBadHash();
			(*hash)->AddData(pbData, *pdwDataLen);
		}
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function encrypts data
BOOL CPEncrypt(IN HCRYPTPROV hProv, IN HCRYPTKEY hKey, IN HCRYPTHASH hHash, IN BOOL fFinal, IN DWORD dwFlags, IN OUT LPBYTE pbData, IN OUT LPDWORD pcbDataLen, IN DWORD cbBufLen)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw ::NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw ::NteBadKey();

		if(pbData!=NULL && hHash!=NULL)
		{
			HashList& hashList = (*prov)->GetHashList();
			HashList::Iterator hash = hashList.find((Hash*)hHash);
			if(hash==hashList.end())
				throw NteBadHash();

			(*hash)->AddData(pbData, cbBufLen);
		}
			
		(*prov)->EncryptedBlock(*key, pbData, pcbDataLen, cbBufLen, fFinal);
	
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function initiates the hashing of a stream of data
BOOL CPCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash)
{
	UNREFERENCED_PARAMETER(dwFlags);
	try
	{
		//Chech  alg id
		if(Algid==NULL)
			throw NteBadAlgID();
	
		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get key
		KeyList::Iterator key = (*prov)->KeyList().end();
		if(hKey!=NULL)
		{
			key = (*prov)->KeyList().find((Key*)hKey);
			if(key==(*prov)->KeyList().end())
				throw NteBadKey();
		}
		
		//Create hash object
		HashList& hashList = (*prov)->GetHashList();
		std::unique_ptr<Hash> hash((*prov)->CreateHash(Algid, hKey!=NULL ? *key : NULL ));
		
		//TODO: flags

		//Save hash object
		hashList.add(hash.get());

		//Return handle by hash object
		*phHash = (HCRYPTHASH)hash.get();
		hash.release();
		
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function destroys the hash object referenced by the hHash parameter
BOOL CPDestroyHash(HCRYPTPROV hProv, HCRYPTHASH hHash)
{
	try
	{
		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();
 
		//Get hash object
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();
	
		//Delete hash
		std::unique_ptr<Hash> removeHash(*hash);  
		hashList.remove(*hash);

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function makes an exact copy of a hash and the state the hash is in
BOOL CPDuplicateHash(HCRYPTPROV hProv, HCRYPTHASH hHash, LPDWORD pdwReserved, DWORD dwFlags, HCRYPTHASH *phHash)
{
	try
	{
		//No params supported
		if(pdwReserved!=NULL)
			throw ErrorInvalidParameter();

		//No flags supported
		if(dwFlags!=NULL)
			throw ErrorInvalidParameter();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw ErrorInvalidParameter();

		//Get hash object
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();
		
		//Clone hash object
		std::unique_ptr<Hash> dupHash((*hash)->Clone());

		//Save hash object
		hashList.add(dupHash.get());

		//Return hash object
		*phHash = (HCRYPTHASH)dupHash.get();
		dupHash.release();
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function retrieves data that governs the operations of a hash object and retrieves the actual hash value
BOOL CPGetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get hash object
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();

		//Get property
		std::shared_ptr<KeyProperty<Hash>> prop = std::shared_ptr<KeyProperty<Hash>>(CreateHashProperty(dwParam, *hash));
		
		//Return property value
		if(pbData!=NULL)
		{
			(*prop).GetProperty(pbData, *pcbDataLen);
		}
		
		//Set propery value size
		*pcbDataLen = (*prop).GetSize();

		return TRUE;
		
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function adds data to a specified hash object
BOOL CPHashData(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD cbDataLen, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get hash object
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();

		//Check hash state
		if((*hash)->IsFinished())
			throw ::NteBadHashState();

		//Add data to hash object
		(*hash)->AddData(pbData, cbDataLen);

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function computes the cryptographic hash of a session key object
BOOL CPHashSessionKey(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags)
{
	try
	{
		//Check flags
		if(dwFlags!=NULL || dwFlags!=CRYPT_LITTLE_ENDIAN)
			throw NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get hash object
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();

		//Get key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hKey);
		if(key==keyList.end())
			throw NteBadKey();

		//Check hash state
		if((*hash)->IsFinished())
			throw ::NteBadHashState();
		
		//Hashed Key
		(*prov)->HashKey(*hash, *key);

		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
	
}

//This function customizes the operations of a hash object
BOOL CPSetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags)
{
	try
	{
		//No flags supported
		if(dwFlags!=NULL)
			throw NteBadFlags();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get hash object
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();

		//Get property
		std::shared_ptr<KeyProperty<Hash>> prop = std::shared_ptr<KeyProperty<Hash>>(CreateHashProperty(dwParam, *hash));
		
		//Set property value
		prop->SetProperty(pbData);
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function signs hash value
BOOL WINAPI CPSignHash(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags, LPBYTE pbSignature, LPDWORD pcbSigLen)
{
	try
	{
		//Check flags
		if(dwFlags!=CRYPT_NOHASHOID && dwFlags!=NULL)
			throw NteBadFlags();

		//Check key specification
		if(dwKeySpec!=AT_KEYEXCHANGE && dwKeySpec!=AT_SIGNATURE)
			throw NteNoKey();

		//This parametr is not supported
		if(szDescription!=NULL)
			throw ::ErrorInvalidParameter();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get hash
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();
	
		//GetKey
		std::shared_ptr<Key> key = std::shared_ptr<Key>((*prov)->GetPermanentKey(dwKeySpec == AT_SIGNATURE));

		//Calculate sign
		(*prov)->CalculateSign(key.get(), *hash, pbSignature, pcbSigLen, dwFlags);
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}

//This function verifies the signature of a hash object
BOOL WINAPI CPVerifySignature(HCRYPTPROV hProv, HCRYPTHASH hHash, CONST BYTE *pbSignature, DWORD cbSigLen, HCRYPTKEY hPubKey,LPCWSTR szDescription, DWORD dwFlags)
{
	try
	{
		//Check flags
		if(dwFlags!=CRYPT_NOHASHOID && dwFlags!=NULL)
			throw NteBadFlags();

		//This parametr is not supported
		if(szDescription!=NULL)
			throw ::ErrorInvalidParameter();

		//Get csp
		ProvStorage::Iterator prov = m_ProvStorage.find((Provider*)hProv);
		if(prov==m_ProvStorage.end())
			throw NteBadUID();

		//Get Hash
		HashList& hashList = (*prov)->GetHashList();
		HashList::Iterator hash = hashList.find((Hash*)hHash);
		if(hash==hashList.end())
			throw NteBadHash();
		
		//Get Key
		KeyList& keyList = (*prov)->KeyList();
		KeyList::Iterator key = keyList.find((Key*)hPubKey);
		if(key==keyList.end())
			throw ::NteBadKey();

		//Verify Sign
		std::vector<BYTE> sign(&pbSignature[0], &pbSignature[0]+cbSigLen);
		if(!(*prov)->VerifySign(*hash, *key, pbSignature, cbSigLen, dwFlags))
			throw NteBadSignature(); 
		
		return TRUE;
	}
	catch(CSPException& ex)
	{
		SetLastError(ex.GetCode());
		return FALSE;
	}
	catch(...)
	{
		SetLastError((DWORD)NTE_FAIL);
		return FALSE;
	}
}
 