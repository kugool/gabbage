
#pragma once

#include<Windows.h>
#include < wincrypt.h >




class SmartTail
{
public:
	SmartTail(void);
	~SmartTail(void);

	bool GetTailData(const char * lpszFilePath,OUT byte* pDataBuf,IN OUT DWORD* pdwLength);
	bool AddTail(const char * lpszFilePath, IN byte* pDataBuf, DWORD dwDataLen);
	bool CutTail(const char * lpszFilePath);
	bool HashFile(const char* pFilePath, int iStartPos, DWORD dwCalculateLen, OUT byte* pHashBuf, OUT DWORD* pLen);
	

private:
	bool m_bParsed;
	DWORD m_dwPaddingLength;
	DWORD m_dwHashLength;
	byte m_FileHash[32];
	

	DWORD m_dwTailLocation;
	DWORD m_dwOriginalFileLength;
	DWORD m_dwFileLength;

	DWORD m_dwTailDataLocation;
	DWORD m_dwTailDataLength;

public:
	bool ParseTail(HANDLE hFileHandle);//parse all info in the tail
	void GetFileMD5(HANDLE hFileHandle, int iStartPos, DWORD dwCalculateLen, OUT byte* pHashBuf, OUT DWORD* pLen);
	void CryptData(IN byte* pbInputData, OUT byte* pbOutputData, IN OUT DWORD* pdwDataLen, byte* pKey, DWORD dwKeyLen, bool bEncrypt);
	DWORD TestTailTip(HANDLE hFileHandle);//test zero tail tip

};

