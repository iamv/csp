#pragma once

#include <Windows.h>
#include <iostream>
#include <memory>
#include <vector>
#include <map>


class FileKeyStorage
{
private:
	static const std::string m_pathToKey;
	static LSTATUS CloseReg(HKEY* key);
	static bool OpenFile(const std::string& fileName );
	static bool DeleteKeyFile(const std::string& fileName);
	static bool CreateNewFile(const std::string& name);
	std::shared_ptr<HKEY> OpenRootReqKey();
	bool ReadContainerPath(std::shared_ptr<HKEY> key, const std::string& name, std::string& path);
	bool ExecuteOperation(const std::string& name, bool (*fileOperation)(const std::string& name), bool deleteRegValue = false);
	
public: 
	FileKeyStorage();
	bool SetPin(const BYTE* pin);
	bool IsKeyExist(const std::string& name);
	bool DeleteKey(const std::string& name);
	bool CreateKey(const std::string& name, const std::string& path);
	bool EnumKey(std::map<std::string, std::string>& containerList);
	bool InstallRootKey();
};
