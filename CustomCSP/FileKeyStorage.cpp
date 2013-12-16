#include "stdafx.h"
#include "FileKeyStorage.h"
#include <string>
#include "CSPException.h"

const std::string FileKeyStorage::m_pathToKey = "Software\\SoftCSP";

LSTATUS FileKeyStorage::CloseReg(HKEY* key)
{
	return RegCloseKey(*key);
}

bool FileKeyStorage::OpenFile(const std::string& fileName )
{
	HANDLE file = CreateFileA(fileName.c_str(),GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file==INVALID_HANDLE_VALUE)
		throw NteKeySetEntryBad(); 
			
	CloseHandle(file);
	return true;
}

bool FileKeyStorage::DeleteKeyFile(const std::string& fileName)
{
	if(DeleteFileA(fileName.c_str())!=TRUE)
		return false;
	return true;
}

bool FileKeyStorage::CreateNewFile(const std::string& name)
{
	HANDLE file = CreateFileA(name.c_str(),GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file==INVALID_HANDLE_VALUE)
		return false;
	CloseHandle(file);
	return true;
}
std::shared_ptr<HKEY> FileKeyStorage::OpenRootReqKey()
{
	InstallRootKey();
	HKEY* ptr_key = new HKEY;
	LSTATUS result = RegOpenKeyExA(HKEY_CURRENT_USER, m_pathToKey.c_str(),0,KEY_ALL_ACCESS,ptr_key);
		
	if(result!=ERROR_SUCCESS)
		throw std::logic_error("Не удалось открыть раздел реестра"); 
		
	std::shared_ptr<HKEY> key(ptr_key, CloseReg);
	return key;
}

bool FileKeyStorage::ReadContainerPath(std::shared_ptr<HKEY> key, const std::string& name, std::string& path)
{
	std::vector<BYTE> value(MAX_PATH+1);
	DWORD typeValue = 0;
	DWORD size = value.size();
			
	LSTATUS readStatus = RegQueryValueExA(*key, name.c_str(), 0, &typeValue, NULL, &size); 	
	if(readStatus==2)//Не забыть выяснить реальное значение ошибки не найден параметр
		return false;
		
	if(readStatus!=ERROR_SUCCESS)
		throw std::logic_error("Не удалось открыть раздел реестра"); 
		
	if(size<1)
		throw std::logic_error("Не удалось прочитать раздел реестра"); 
	value.resize(size);

	readStatus = RegQueryValueExA(*key, name.c_str(), 0, &typeValue, &value[0], &size); 		
	if(readStatus==2)//Не забыть выяснить реальное значение ошибки не найден параметр
		return false;
		
	if(readStatus!=ERROR_SUCCESS)
		throw std::logic_error("Не удалось открыть раздел реестра"); 
			
	std::string fileName(value.begin(), value.begin()+size);
	path = fileName;
	return true;
}
	
bool FileKeyStorage::ExecuteOperation(const std::string& name, bool (*fileOperation)(const std::string& name), bool deleteRegValue)
{	
	std::shared_ptr<HKEY> key = NULL;
		
	
	key = OpenRootReqKey();
	
	std::string filePath;
	bool isRegKey = ReadContainerPath(key, name, filePath);
	if(!isRegKey)
		return false;
	bool result = fileOperation(filePath);
	if(result==false)
		throw NteKeySetEntryBad();
	if(deleteRegValue)
	{
		return RegDeleteKeyValueA(*key,NULL,name.c_str()) == ERROR_SUCCESS ? true : false;
	}
	return result;
}
	
FileKeyStorage::FileKeyStorage()
{
}
bool FileKeyStorage::SetPin(const BYTE* pin)
{
	UNREFERENCED_PARAMETER(pin);
	return false;
}
bool FileKeyStorage::IsKeyExist(const std::string& name)
{
	return ExecuteOperation(name, OpenFile);
}
bool FileKeyStorage::DeleteKey(const std::string& name)
{
	return ExecuteOperation(name, DeleteKeyFile, true);	
}
bool FileKeyStorage::CreateKey(const std::string& name, const std::string& path)
{
	std::map<std::string,std::string> listKey;
	EnumKey(listKey);
	if(IsKeyExist(name))
		return false;
	std::shared_ptr<HKEY> key = OpenRootReqKey();
	if(RegSetKeyValueA(*key, NULL, name.c_str(), REG_SZ, path.c_str(), path.length())!=ERROR_SUCCESS)
		return false;
	return CreateNewFile(path);
}
bool FileKeyStorage::EnumKey(std::map<std::string, std::string>& containerList)
{
	std::shared_ptr<HKEY> key = OpenRootReqKey();
	int i =0;
	bool lastValue = false;
	while(!lastValue)
	{
		DWORD len =MAX_PATH;
		DWORD type = 0;
		DWORD sizeValue;
		std::vector<CHAR> nameVal(MAX_PATH+1);
		LSTATUS resultOperation = RegEnumValueA(*key, i, &nameVal[0], &len, 0, &type, NULL, &sizeValue);
		if(resultOperation!=ERROR_SUCCESS)
		{
			return resultOperation == ERROR_NO_MORE_ITEMS;
		}
		//sizeValue+=100;
		std::vector<BYTE> value(sizeValue);
		len++;
		resultOperation = RegEnumValueA(*key, i, &nameVal[0], &len, 0, &type, &value[0], &sizeValue);
		i++;
		if(resultOperation!=ERROR_SUCCESS && resultOperation != ERROR_NO_MORE_ITEMS)
			return false;
		std::string name(nameVal.begin(), nameVal.begin() + len);
		std::string path(value.begin(), value.begin()+sizeValue);
		std::pair<std::string, std::string> pair = std::pair<std::string, std::string>(name,path);
		containerList.insert(pair);
		lastValue = resultOperation == ERROR_NO_MORE_ITEMS;
	}
	return true;
}
bool FileKeyStorage::InstallRootKey()
{
	HKEY* ptr_key = new HKEY;
	DWORD isNewKey = 0;
	LSTATUS result = 
	RegCreateKeyExA(HKEY_CURRENT_USER, m_pathToKey.c_str(), 0, "", REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, ptr_key, &isNewKey);
	if(result!=ERROR_SUCCESS)
		return false;
		
	RegCloseKey(*ptr_key);
		
	return true;
}
