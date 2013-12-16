#pragma once
#include <Windows.h>
#include <WinCrypt.h>
#include "common.h"

BOOL CPReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL CPAcquireContext(HCRYPTPROV* phProv, CHAR* pszContainer, DWORD dwFlags, PVTableProvStruc pVTable);
BOOL CPGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen,DWORD dwFlags);
BOOL CPSetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD dwFlags);
BOOL CPGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);
BOOL CPGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY* phUserKey);
BOOL CPCreateHash(HCRYPTPROV hProv,ALG_ID Algid,HCRYPTKEY hKey, DWORD dwFlags,HCRYPTHASH *phHash);
BOOL CPDuplicateHash(HCRYPTPROV hProv, HCRYPTHASH hHash, LPDWORD pdwReserved, DWORD dwFlags, HCRYPTHASH *phHash);
BOOL CPDestroyHash(IN HCRYPTPROV hProv, IN HCRYPTHASH hHash);
BOOL CPSetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, CONST BYTE *pbData, DWORD dwFlags);
BOOL CPGetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags);
BOOL CPHashData(HCRYPTPROV hProv, HCRYPTHASH hHash, BYTE *pbData, DWORD cbDataLen, DWORD dwFlags);
BOOL CPHashSessionKey(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags);

void TestCSP(); //TODO: удалить