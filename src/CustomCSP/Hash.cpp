#include "stdafx.h"
//#include "Hash.h"
//#include "CSPException.h"
//Hash::Hash(ALG_ID id):IAlg(id)
//{
//}
//void Hash::Update(std::vector<BYTE>&)
//{
//	throw NteNoSupported();
//}
//
//bool Hash::IsFinished() const
//{
//	return m_isFinished; 
//}
//void Hash::AddData(CONST BYTE *pbData, DWORD cbDataLen)
//{
//	if(m_isFinished)
//		throw NteBadHash();
//	std::vector<BYTE> data(&pbData[0], &pbData[0] + cbDataLen);
//	Update(data);
//}
//void Hash::ResetBuffer(std::vector<BYTE>& newData)
//{
//	UNREFERENCED_PARAMETER(newData);
//	throw NteNoSupported();
//}
//void Hash::SetValue(const BYTE* data)
//{
//	if(m_isFinished)
//		throw NteBadHash();
//	std::vector<BYTE> newData(&data[0], &data[0] + GetHashSize());
//	ResetBuffer(newData);
//
//	/*std::vector<BYTE> temp;
//
//	temp.resize(HASH_SIZE);
//	int j =0;
//	for(std::vector<BYTE>::iterator i = temp.begin(); i!=temp.end(); ++i, ++j)
//	{
//		*i = data[j];
//	}
//
//	temp.swap(m_value);*/
//}
//DWORD Hash::GetHashSize() const
//{
//	return m_hashSize;
//}
//
//ALG_ID Hash::getAlgId() const
//{
//	return m_algId;
//}
//Hash::Hash(ALG_ID algId, DWORD size, Key* key, Buffer* buffer)
//	:IAlg(algId), m_algId(algId), m_key(key), m_hashSize(size), m_isFinished(false), m_buffer(buffer)
//{
//}
//Hash::Hash(const Hash& over):IAlg(over.m_algId)
//{
//	//if(this!=&over)
//	//{
//	//	Hash temp(over.m_algId);
//	//	temp.m_algId = over.m_algId;
//	//	temp.m_isFinished = over.m_isFinished;
//	//	temp.m_key = over.m_key; //Мы никогда не освобождаем этот ресурс. Это не ошибка
//	//	temp.m_buffer = over.m_buffer;
//	//	temp.m_state = over.m_state;
//	//	temp.m_hashSize = over.m_hashSize;
//	//	temp.swap(*this);
//	//} //TODO: переделать на интерфейс
//}
//
//void Hash::swap(Hash& over)
//{
//	std::swap(m_algId, over.m_algId);
//	std::swap(m_isFinished, over.m_isFinished);
//	std::swap(m_key, over.m_key);
//	std::swap(m_buffer, over.m_buffer);
//	std::swap(m_state, over.m_state);
//	std::swap(m_hashSize, over.m_hashSize);
//	m_buffer.swap(over.m_buffer);
//}
//
//Hash* Hash::Clone()
//{
//	Hash* hash = new Hash(*this);
//	return hash;
//}
//
//void Hash::Finished(std::vector<BYTE>&)
//{
//	throw NteNoSupported();
//}
//
//void Hash::ReOpen()
//{
//	m_isFinished = true;
//}
//
//bool Hash::GetHashValue(BYTE* hashVal, DWORD hashValSize)
//{
//	DWORD size = GetHashSize();
//	if(size > hashValSize)
//		return false;
//	std::vector<BYTE> result(size);
//	Finished(result);
//	std::_Copy_impl(result.begin(), result.end(), &hashVal[0]);
//	m_isFinished = true;
//	return true;
//}
