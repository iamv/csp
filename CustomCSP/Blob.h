#pragma once
#include <WinCrypt.h>

class Blob
{
public:
	enum BlobType {PublicKey = PUBLICKEYBLOB, PrivateKey = PRIVATEKEYBLOB, Simple = SIMPLEBLOB};
	static BlobType CreateBlobType(DWORD type)
	{
		switch(type)
		{
			case PUBLICKEYBLOB: return PublicKey; break;
			case PRIVATEKEYBLOB: return PrivateKey; break;
			case SIMPLEBLOB: return Simple; break;
		};

		throw ::NteBadType();
	}
};