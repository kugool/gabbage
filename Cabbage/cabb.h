#ifndef _CABB_H_
#define _CABB_H_

#include <windows.h>

bool ProduceRandomNumberCrypt(BYTE* lpRandomBytes,DWORD dwSize);
bool CreateTempFileName(char* szTempFileName, DWORD dwLength);

class Cabbage
{
public:

	bool EnCabFile(const char* oriFile, const char* tarFile);
	bool DeCabFile(const char* oriFile, const char* tarFile);

private:
	bool FileEncrypt(const char* oriFile, const char* tarFile, BYTE* lpChaos, DWORD dwChaosLen);
	bool FileDecrypt(const char* oriFile, const char* tarFile, BYTE* lpChaos, DWORD dwChaosLen);
	bool FileCrypt(const char* oriFile, const char* tarFile, BYTE* lpChaos, DWORD dwChaosLen, bool bEncrypt);
};

#endif