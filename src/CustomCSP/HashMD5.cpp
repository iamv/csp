#include "stdafx.h"
#include "HashMD5.h"
#include <WinCrypt.h>
#include "CSPException.h"

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

bool HashMD5::IsFinished() const
{
	return m_isFinished;
}
void HashMD5::AddData(const BYTE *pbData, DWORD cbDataLen)
{
	if(m_isFinished)
		throw NteBadHash();
	std::vector<BYTE> data(&pbData[0], &pbData[0] + cbDataLen);
	Update(data);
}

void HashMD5::SetValue(const BYTE*)
{
	throw ::NteNoSupported(); //TODO: реализовать
}

Key* HashMD5::CreateKey(DWORD, bool, bool) const
{
	throw ::NteNoSupported();
}
Key* HashMD5::ImportKey(const BYTE*, DWORD) const
{
	throw ::NteNoSupported();
}

DWORD HashMD5::GetIncrementKeySize() const
{
	throw ::NteNoSupported();
}
void HashMD5::ReOpen()
{
	m_isFinished = true;
}

HashMD5* HashMD5::Clone() const
{
	HashMD5 * newHash = new HashMD5;
	newHash->m_buffer = m_buffer;
	
	newHash->m_hashSize = m_hashSize;
	newHash->m_isFinished = m_isFinished;
	newHash->m_state = m_state;

	return newHash;
}

DWORD HashMD5::GetHashSize() const
{
	return m_hashSize;
}

bool HashMD5::GetHashValue(BYTE* hashVal, DWORD hashValSize)
{
	DWORD size = GetHashSize();
	if(size > hashValSize)
		return false;
	std::vector<BYTE> result(size);
	Finished(result); //TODO: ошибка если вызвать метод 2 раза, то будет ошибка
	std::_Copy_impl(result.begin(), result.end(), &hashVal[0]);
	m_isFinished = true;
	return true;
}


HashMD5::HashMD5(): Hash(CALG_MD5, 128, 128, 128, 0x0007, L"MD5", L"MD5"), m_hashSize(16), m_buffer(new Buffer64)
{
	m_state.resize(6);
	m_state[0]=0x67452301;
	m_state[1]=0xEFCDAB89;
	m_state[2]=0x98BADCFE;
	m_state[3]=0x10325476;
	m_state[4]=0;
	m_state[5]=0;
}

void HashMD5::Update(std::vector<BYTE>&data)
{
	DWORD size = data.size();	
	DWORD countBits = size<<3;
	
	//увеличиваем счетчик бит в сообщении
	//проверяем на переполнение
	if((m_state[4] + countBits) < m_state[4])
		m_state[5]++;
	m_state[4] += countBits;
	m_state[5] += size>>29;
		
		
	//в последем раунде шифрование может не производиться 
	DWORD round =0;
	while(size>0)
	{
		size-= m_buffer->SetValue(&data[0]+round*64,size>64 ? 64 : size);
		round++;
		BYTE chank[64];
		if(m_buffer->GetValue(chank)<64)
			break;
		Round(chank);
	}
}

unsigned long HashMD5::R(unsigned long a, unsigned long b, unsigned long c, unsigned long d, unsigned long x, unsigned long s, unsigned long int ac, unsigned long (*func)(unsigned long x, unsigned long y, unsigned long z))
{
	a += func(b,c,d) + x + ac;
	a = RotateLeft(a, s);
	a += b;
	return a;
}

void HashMD5::Round(unsigned char* block)
{
	unsigned long a = m_state[0];
	unsigned long b = m_state[1];
	unsigned long c = m_state[2];
	unsigned long d = m_state[3];
	//получаем 16 байт
	unsigned long x[16];
	Decode (x, block, 64);
	// Round 1 			
	a = R(a, b, c, d, x[ 0], S11, 0xd76aa478, F); 
	d = R(d, a, b, c, x[ 1], S12, 0xe8c7b756, F);
	c = R(c, d, a, b, x[ 2], S13, 0x242070db, F); 
	b = R(b, c, d, a, x[ 3], S14, 0xc1bdceee, F); 
	a = R(a, b, c, d, x[ 4], S11, 0xf57c0faf, F); 
	d = R(d, a, b, c, x[ 5], S12, 0x4787c62a, F); 
	c = R(c, d, a, b, x[ 6], S13, 0xa8304613, F); 
	b = R(b, c, d, a, x[ 7], S14, 0xfd469501, F); 
	a = R(a, b, c, d, x[ 8], S11, 0x698098d8, F); 
	d = R(d, a, b, c, x[ 9], S12, 0x8b44f7af, F); 
	c = R(c, d, a, b, x[10], S13, 0xffff5bb1, F); 
	b = R(b, c, d, a, x[11], S14, 0x895cd7be, F);
	a = R(a, b, c, d, x[12], S11, 0x6b901122, F); 
	d = R(d, a, b, c, x[13], S12, 0xfd987193, F); 
	c = R(c, d, a, b, x[14], S13, 0xa679438e, F); 
	b = R(b, c, d, a, x[15], S14, 0x49b40821, F); 
 	
	// Round 2
	a = R(a, b, c, d, x[ 1], S21, 0xf61e2562, G); 
	d = R(d, a, b, c, x[ 6], S22, 0xc040b340, G); 
	c = R(c, d, a, b, x[11], S23, 0x265e5a51, G); 
	b = R(b, c, d, a, x[ 0], S24, 0xe9b6c7aa, G);
	a = R(a, b, c, d, x[ 5], S21, 0xd62f105d, G); 
	d = R(d, a, b, c, x[10], S22, 0x2441453,  G); 
	c = R(c, d, a, b, x[15], S23, 0xd8a1e681, G); 
	b = R(b, c, d, a, x[ 4], S24, 0xe7d3fbc8, G); 
	a = R(a, b, c, d, x[ 9], S21, 0x21e1cde6, G);
	d = R(d, a, b, c, x[14], S22, 0xc33707d6, G); 
	c = R(c, d, a, b, x[ 3], S23, 0xf4d50d87, G);
	b = R(b, c, d, a, x[ 8], S24, 0x455a14ed, G); 
	a = R(a, b, c, d, x[13], S21, 0xa9e3e905, G); 
	d = R(d, a, b, c, x[ 2], S22, 0xfcefa3f8, G); 
	c = R(c, d, a, b, x[ 7], S23, 0x676f02d9, G); 
	b = R(b, c, d, a, x[12], S24, 0x8d2a4c8a, G);

	//Round 3 
	a = R(a, b, c, d, x[ 5], S31, 0xfffa3942, H);
	d = R(d, a, b, c, x[ 8], S32, 0x8771f681, H); 
	c = R(c, d, a, b, x[11], S33, 0x6d9d6122, H);
	b = R(b, c, d, a, x[14], S34, 0xfde5380c, H); 
	a = R(a, b, c, d, x[ 1], S31, 0xa4beea44, H); 
	d = R(d, a, b, c, x[ 4], S32, 0x4bdecfa9, H); 
	c = R(c, d, a, b, x[ 7], S33, 0xf6bb4b60, H); 
	b = R(b, c, d, a, x[10], S34, 0xbebfbc70, H); 
	a = R(a, b, c, d, x[13], S31, 0x289b7ec6, H);
	d = R(d, a, b, c, x[ 0], S32, 0xeaa127fa, H); 
	c = R(c, d, a, b, x[ 3], S33, 0xd4ef3085, H); 
	b = R(b, c, d, a, x[ 6], S34, 0x4881d05,  H); 
	a = R(a, b, c, d, x[ 9], S31, 0xd9d4d039, H); 
	d = R(d, a, b, c, x[12], S32, 0xe6db99e5, H);
	c = R(c, d, a, b, x[15], S33, 0x1fa27cf8, H);
	b = R(b, c, d, a, x[ 2], S34, 0xc4ac5665, H); 
 	
	//Round 4
	a = R(a, b, c, d, x[ 0], S41, 0xf4292244, I); 
	d = R(d, a, b, c, x[ 7], S42, 0x432aff97, I); 
	c = R(c, d, a, b, x[14], S43, 0xab9423a7, I);
	b = R(b, c, d, a, x[ 5], S44, 0xfc93a039, I); 
	a = R(a, b, c, d, x[12], S41, 0x655b59c3, I);
	d = R(d, a, b, c, x[ 3], S42, 0x8f0ccc92, I); 
	c = R(c, d, a, b, x[10], S43, 0xffeff47d, I);
	b = R(b, c, d, a, x[ 1], S44, 0x85845dd1, I); 
	a = R(a, b, c, d, x[ 8], S41, 0x6fa87e4f, I); 
	d = R(d, a, b, c, x[15], S42, 0xfe2ce6e0, I); 
	c = R(c, d, a, b, x[ 6], S43, 0xa3014314, I);
	b = R(b, c, d, a, x[13], S44, 0x4e0811a1, I); 
	a = R(a, b, c, d, x[ 4], S41, 0xf7537e82, I);
	d = R(d, a, b, c, x[11], S42, 0xbd3af235, I); 
	c = R(c, d, a, b, x[ 2], S43, 0x2ad7d2bb, I); 
	b = R(b, c, d, a, x[ 9], S44, 0xeb86d391, I); 
	
	m_state[0] += a;
	m_state[1] += b;
	m_state[2] += c;
	m_state[3] += d;
}

void HashMD5::Finished(std::vector<BYTE>& result)
{
	BYTE chank[64];
	DWORD size = m_buffer->GetValue(chank);
	DWORD overflow = 56 - size;
	if(overflow<0)
		overflow = 120 - size;
	chank[size]=0x80;
	for(DWORD i=1 ; i < overflow; ++i)
		chank[i+size]=0;

	BYTE lenData[8];
	
	Encode(lenData, &m_state[4], 8);
	chank[63]=lenData[7];
	chank[62]=lenData[6];
	chank[61]=lenData[5];
	chank[60]=lenData[4];
	chank[59]=lenData[3];
	chank[58]=lenData[2];
	chank[57]=lenData[1];
	chank[56]=lenData[0];
	Round(chank);

	BYTE temp[4];

	Encode(temp, &m_state[0], 4);
	result[0]=temp[0];
	result[1]=temp[1];
	result[2]=temp[2];
	result[3]=temp[3];

	Encode(temp, &m_state[1], 4);
	result[4]=temp[0];
	result[5]=temp[1];
	result[6]=temp[2];
	result[7]=temp[3];
	
	Encode(temp, &m_state[2], 4);
	result[8]=temp[0];
	result[9]=temp[1];
	result[10]=temp[2];
	result[11]=temp[3];
	
	Encode(temp, &m_state[3], 4);
	result[12]=temp[0];
	result[13]=temp[1];
	result[14]=temp[2];
	result[15]=temp[3];
}

void HashMD5::Decode (DWORD *output, BYTE *input, DWORD len)
{
 	unsigned int i;
	unsigned int j; 	
	for (i = 0, j = 0; j < len; i++, j += 4)
	{
		output[i] = ((unsigned long int)input[j]) |
	 	(((unsigned long int)input[j+1]) << 8) |
 		(((unsigned long int)input[j+2]) << 16) |
 		(((unsigned long int)input[j+3]) << 24);
 	}
}
void HashMD5::Encode(BYTE* output, DWORD* input, DWORD size)
{
	UINT i = 0;  
	UINT j = 0;  
	for (;j < size; i++, j += 4)  
	{  
		output[j] =   (UCHAR)(input[i] & 0xff);  
		output[j+1] = (UCHAR)((input[i] >> 8) & 0xff);  
		output[j+2] = (UCHAR)((input[i] >> 16) & 0xff);  
		output[j+3] = (UCHAR)((input[i] >> 24) & 0xff);  
	}  
}

unsigned long HashMD5::F(unsigned long x, unsigned long y, unsigned long z)
{
	return (x & y) | (~x & z);
}
unsigned long HashMD5::G(unsigned long x, unsigned long y, unsigned long z)
{
	return (x & z) | (y & ~z);
}
unsigned long HashMD5::H(unsigned long x, unsigned long y, unsigned long z)
{
	return x ^ y ^ z;
}
unsigned long HashMD5::I(unsigned long x, unsigned long y, unsigned long z)
{
	return y ^ (x | ~z);
}
unsigned long HashMD5::RotateLeft(unsigned long x, unsigned long n)
{
	return ((x) << (n)) | ((x) >> (32-(n)));
}
