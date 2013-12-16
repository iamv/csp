#pragma once
#include <Windows.h>
#include <vector>
#include "Buffer.h"
#include "Alg.h"
class Key;

class Hash : public IAlg
{
public: 
	Hash(ALG_ID id, DWORD defaultLen, DWORD minLen, DWORD maxLen, DWORD protocols, const std::wstring& name, const std::wstring& longName): IAlg(id, defaultLen, minLen, maxLen, protocols, name, longName)
	{

	}
	virtual ~Hash()
	{

	}
	virtual Hash* Clone() const = 0;
	virtual bool IsFinished() const =0;
	virtual void AddData(const BYTE *pbData, DWORD cbDataLen)=0;
	virtual void SetValue(const BYTE* data)=0;
	virtual bool GetHashValue(BYTE* hashVal, DWORD hashValSize) =0;
	virtual DWORD GetHashSize() const =0;
	virtual void ReOpen() =0;
};

//#define HASH_SIZE 8
//
//class Hash : public IAlg
//{
//protected:
//	Key* m_key; //Мы никогда не освобождаем этот ресурс. Это не ошибка
//	ALG_ID m_algId;
//	bool m_isFinished;
//	DWORD m_hashSize;
//	std::shared_ptr<Buffer> m_buffer;
//	std::vector<DWORD> m_state;
//	//std::vector<BYTE> m_value;
//private:
//	virtual void Update(std::vector<BYTE>&data);
//	virtual void ResetBuffer(std::vector<BYTE>& newData);
//	virtual void Finished(std::vector<BYTE>& result);
//	Hash(ALG_ID id);
//	virtual Key* CreateKey(DWORD size, bool salt, bool exportable) const = 0;
//public:
//	bool IsFinished() const;
//	void AddData(CONST BYTE *pbData, DWORD cbDataLen);
//	void SetValue(const BYTE* data);
//	DWORD GetHashSize() const;
//	ALG_ID getAlgId() const;
//	void ReOpen();
//	
//	Hash(ALG_ID algId, DWORD size, Key* key, Buffer* buffer);
//	Hash(const Hash& over);
//	void swap(Hash& over);
//	Hash* Clone();
//	bool GetHashValue(BYTE* hashVal, DWORD hashValSize);
//};