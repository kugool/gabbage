#include "SmartTail.h"
#include <stdio.h>
#include <time.h>

#define BUFSIZE 1024
#define HASHLEN  64

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC2 
#define ENCRYPT_BLOCK_SIZE 8 

#define CHECK_NULL_RET(bCondition) if (!bCondition) goto EXIT0


SmartTail::SmartTail(void)
{
	m_bParsed = false;

	m_dwPaddingLength = 0;
	m_dwHashLength = 0;
	ZeroMemory(m_FileHash, sizeof(m_FileHash));

	m_dwTailLocation = 0;
	m_dwOriginalFileLength = 0;
	m_dwFileLength = 0;
	m_dwTailDataLocation = 0;
	m_dwTailDataLength= 0;
}


SmartTail::~SmartTail(void)
{
}
///////////////////////////////////////////////////////////////
//call GetFileMD5() to get a hash value of a file
//
//////////////////////////////////////////////////////////////
bool SmartTail::HashFile(const char* pszFilePath, int iStartPos, DWORD dwCalculateLen, OUT byte* pHashBuf, OUT DWORD* pLen)
{
	HANDLE hFile = CreateFile((TCHAR *)pszFilePath,
							GENERIC_READ,
							FILE_SHARE_READ,
							NULL,
							OPEN_EXISTING,
							NULL/*FILE_FLAG_SEQUENTIAL_SCAN*/,
							NULL);
	if(INVALID_HANDLE_VALUE == hFile)
		return false;

	GetFileMD5(hFile, iStartPos, dwCalculateLen, pHashBuf, pLen);

	CloseHandle(hFile);

	if(*pLen > 0)
		return true;
	else
		return false;

}
///////////////////////////////////////////////////////////////
//calculate file md5 hash from target data section
//position -1 means from bgeinning of the file
////////////////////////////////////////////////////////////
void SmartTail::GetFileMD5(HANDLE hFileHandle, int iStartPos, DWORD dwCalculateLen, OUT byte* pHashBuf, OUT DWORD* pLen)
{
	//save file pointer. Important !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	DWORD dwOriginalFilePointer = SetFilePointer(hFileHandle, 0, NULL, FILE_CURRENT);

	HCRYPTPROV hProv;
    HCRYPTHASH hHash;

	BOOL bResult = FALSE;

    bResult = CryptAcquireContext(&hProv,
								NULL,
								NULL/*MS_ENHANCED_PROV*/,
								PROV_RSA_FULL,
								CRYPT_VERIFYCONTEXT);
	CHECK_NULL_RET(bResult);
 
    bResult = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CHECK_NULL_RET(bResult);


	DWORD dwFileLength = GetFileSize(hFileHandle, NULL);
	DWORD dwTotalToRead = 0;

	//---------------------------------------------------------------------------------------------
	//calculate start position and length
	if(iStartPos <= -1)
	{//read from beginning
		SetFilePointer(hFileHandle, 0, NULL, FILE_BEGIN);
		dwTotalToRead = dwFileLength;
	}
	else
	{
		bResult = (dwCalculateLen > 0 && (iStartPos + dwCalculateLen <= dwFileLength))? TRUE : FALSE;
		CHECK_NULL_RET(bResult);

		SetFilePointer(hFileHandle,iStartPos, NULL, FILE_BEGIN);
		dwTotalToRead = dwCalculateLen;
	}
	

	DWORD dwBytesRead = 0;
	BYTE readBuf[BUFSIZE] = {0};
	DWORD dwOnceToRead = 0;
	//---------------------------------------------------------------------------------------------
	//read all data in a loop
	while (dwTotalToRead > 0)
    {
		dwOnceToRead = (dwTotalToRead >= BUFSIZE) ? BUFSIZE : dwTotalToRead;
		
		bResult = ReadFile(hFileHandle, readBuf, dwOnceToRead, &dwBytesRead, NULL);
		CHECK_NULL_RET(bResult);

        if (0 == dwBytesRead)
        {
            break;
        }
		dwTotalToRead -= dwBytesRead;
 
        bResult = CryptHashData(hHash, readBuf, dwBytesRead, 0);
        CHECK_NULL_RET(bResult);
    }

	//---------------------------------------------------------------------------------------------
	//get hash value from hash object
	BYTE pTempBuf[HASHLEN+4] = {0};
	DWORD dwLen = HASHLEN + 4;
    if (bResult = CryptGetHashParam(hHash, HP_HASHVAL, pTempBuf, &dwLen, 0))
	{
		memcpy((void*)pHashBuf, pTempBuf, dwLen);
		*pLen = dwLen;
	}
	CHECK_NULL_RET(bResult);

EXIT0:
	if(!bResult)
	{
		*pLen = 0;
	}
	if(hHash != 0)
	{	
		CryptDestroyHash(hHash);
	}
	if(hProv != 0)
	{
		CryptReleaseContext(hProv, 0);
	}
    
	//recover file pointer
	SetFilePointer(hFileHandle, dwOriginalFilePointer, NULL, FILE_BEGIN);

	return;
}


//////////////////////////////////////////////////////////////////////////
//tail tip test , find zero string from file end
//
///////////////////////////////////////////////////////////////////////////

DWORD SmartTail::TestTailTip(HANDLE hFileHandle)
{
	//save file pointer. Important !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	DWORD dwOriginalFilePointer = SetFilePointer(hFileHandle, 0, NULL, FILE_CURRENT);
	
	DWORD dwFileLength = GetFileSize(hFileHandle, NULL);

	DWORD dwReadLength = (dwFileLength < 255)? dwFileLength : 256;

	BYTE lpTipData[256] = {0};
	DWORD dwBytesRead = 0;

	__try
	{
			SetFilePointer(hFileHandle, (-1)*dwReadLength, NULL, FILE_END);
			if(!ReadFile(hFileHandle, lpTipData, dwReadLength, &dwBytesRead, NULL))
			{
				return 0;
			}

			DWORD dwZeroCount = 0;
			for(int i= dwBytesRead-1; i>0; i--)
			{
				if(lpTipData[i] == 0)
					dwZeroCount ++;
				else
				{
					if(lpTipData[i] == dwZeroCount)
					{
						return dwZeroCount+1;
					}
					else
					{
						return 0;
					}
				
				}
			}
	}
	__finally
	{
			//recover file pointer
			SetFilePointer(hFileHandle, dwOriginalFilePointer, NULL, FILE_BEGIN);
	}


	return 0;
}


////////////////////////////////////////////////////////////////////////////
//parse all info in tail if the file has a tail
//
////////////////////////////////////////////////////////////////////////////
bool SmartTail::ParseTail(HANDLE hFileHandle)
{
	//save file pointer. Important !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	DWORD dwOriginalFilePointer = SetFilePointer(hFileHandle, 0, NULL, FILE_CURRENT);
	
	bool bResult = false;
	DWORD dwTipLength = 0;
	DWORD dwFileLength = 0;
	

	dwFileLength = GetFileSize(hFileHandle, NULL);

	__try
	{
		//---------------------------------------------------------------------------------------------
		//tail tip test
		if((dwTipLength = TestTailTip(hFileHandle)) == 0)
			return false;


		DWORD dwTailBodyLen = 0;
		DWORD dwBytesRead = 0;
		DWORD dwFileHashLen = 0;
		DWORD dwTailLocation = 0;
		byte  MD5Hash[24] = {0};
		byte  FileHash[24] = {0};
		DWORD dwOriginalFileLen = 0;
		DWORD dwTailDataLength = 0;
		DWORD dwTailDataLocation = 0;

		//---------------------------------------------------------------------------------------------
		//read tail body len
		SetFilePointer(hFileHandle,(-1)*(dwTipLength+4), NULL, FILE_END);
		if(!ReadFile(hFileHandle, (void*)&dwTailBodyLen, 4, &dwBytesRead, NULL))
			return false;

		dwTailLocation = dwFileLength - dwTipLength - 4 - dwTailBodyLen;

		//---------------------------------------------------------------------------------------------
		//read hash in file
		SetFilePointer(hFileHandle,dwTailLocation, NULL, FILE_BEGIN);
		if(!ReadFile(hFileHandle, (void*)MD5Hash, 16, &dwBytesRead, NULL))
			return false;

		//---------------------------------------------------------------------------------------------
		//read original file len
		if(!ReadFile(hFileHandle, (void*)&dwOriginalFileLen, 4, &dwBytesRead, NULL))
			return false;

		//---------------------------------------------------------------------------------------------
		//file length error test
		if(dwOriginalFileLen >= dwTailLocation)
			return false;

		//---------------------------------------------------------------------------------------------
		//calculate original file hash
		GetFileMD5(hFileHandle, 0, dwOriginalFileLen, FileHash, &dwFileHashLen);
		if(dwFileHashLen == 0)
			return false;

		//---------------------------------------------------------------------------------------------
		//compare hash value
		if(memcmp(FileHash, MD5Hash, dwFileHashLen) != 0)
			return false;

		//---------------------------------------------------------------------------------------------
		//locate tail data
		if(!ReadFile(hFileHandle, &dwTailDataLength, 4, &dwBytesRead, NULL))
			return false;
		dwTailDataLocation = dwTailLocation + dwFileHashLen + sizeof(dwOriginalFileLen) + sizeof(dwTailDataLength);

		//---------------------------------------------------------------------------------------------
		//test all length
		if(dwTailDataLocation + dwTailDataLength + sizeof(dwTailBodyLen) + dwTipLength != dwFileLength )
			return false;

		//---------------------------------------------------------------------------------------------
		//save info in tail to member value
		m_dwPaddingLength = dwTailLocation - dwOriginalFileLen;
		m_dwHashLength = dwFileHashLen;
		memcpy(m_FileHash, FileHash, dwFileHashLen);

		m_dwTailLocation = dwTailLocation;
		m_dwOriginalFileLength = dwOriginalFileLen;
		m_dwFileLength = dwFileLength;
		m_dwTailDataLocation = dwTailDataLocation;
		m_dwTailDataLength= dwTailDataLength;

		bResult = true;

	}
	__finally
	{
		//recover file pointer
		SetFilePointer(hFileHandle, dwOriginalFilePointer, NULL, FILE_BEGIN);

		m_bParsed = bResult;

	}

	return m_bParsed;

}


///////////////////////////////////////////////////////////////////////////////
//add some data to a file end ,the data will be encrypted by the file hash
//this function could be called many times, so the file could have a tail after another
//////////////////////////////////////////////////////////////////////////////
bool SmartTail::AddTail(const char * lpszFilePath, IN byte* pData, DWORD dwDataLen)
{
	byte Padding[200];
	DWORD dwPaddingLength = 0;

	byte FileHash[32] = {0};
	DWORD dwFileHashLen = 0;

	DWORD dwFileLength = 0;
	DWORD dwTailDataLength = 0;

	DWORD dwTailBodyLength = 0;
	DWORD dwTotalLength = 0;

	HANDLE	hFile = CreateFile((TCHAR *)lpszFilePath,
							GENERIC_WRITE|GENERIC_READ,
							FILE_SHARE_READ,
							NULL,
							OPEN_EXISTING,
							NULL/*FILE_FLAG_SEQUENTIAL_SCAN*/,
							NULL);

	if(hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	//---------------------------------------------------------------------------------------------
	//get file length
	dwFileLength = GetFileSize(hFile, NULL);

	//---------------------------------------------------------------------------------------------
	//make padding
	srand( (unsigned)time( NULL ) );
	dwPaddingLength = (rand() % 100) + 64;
	for(int i = 0 ; i < dwPaddingLength; i++)
		Padding[i] = rand()%255;

	//---------------------------------------------------------------------------------------------
	//make hash
	GetFileMD5(hFile, -1, 0, FileHash, &dwFileHashLen);

	//---------------------------------------------------------------------------------------------
	//encrypt data by hash
	DWORD dwLength = dwDataLen;
	byte* pEncryptDataBuffer = (byte*)malloc(dwDataLen + 16);
	CryptData(pData, pEncryptDataBuffer, &dwLength, FileHash, dwFileHashLen, true);

	dwTailDataLength = dwLength;

	//---------------------------------------------------------------------------------------------
	//make body length
	dwTailBodyLength = dwFileHashLen + sizeof(dwFileLength) + sizeof(dwTailDataLength) + dwTailDataLength;

	//---------------------------------------------------------------------------------------------
	//make tail tip
	byte ZeroTip[256] = {0};
	DWORD dwTipZeroCount = rand()%254 +1;
	ZeroTip[0] = (byte)dwTipZeroCount;

	//---------------------------------------------------------------------------------------------
	//count total length for buffer
	dwTotalLength = dwPaddingLength + dwTailBodyLength + sizeof(dwTailBodyLength) + 1 + dwTipZeroCount;

	//---------------------------------------------------------------------------------------------
	//make the whole tail in memory
	byte* pDataBuffer = (byte*)malloc(dwTotalLength+4);
	DWORD dwIndex = 0;
	memcpy((void*)(pDataBuffer+dwIndex), Padding, dwPaddingLength);
	dwIndex += dwPaddingLength;
	memcpy((void*)(pDataBuffer+dwIndex), FileHash, dwFileHashLen);
	dwIndex += dwFileHashLen;
	memcpy((void*)(pDataBuffer+dwIndex), (void*)&dwFileLength, sizeof(dwFileLength));
	dwIndex += sizeof(dwFileLength);
	memcpy((void*)(pDataBuffer+dwIndex), (void*)&dwTailDataLength, sizeof(dwTailDataLength));
	dwIndex += sizeof(dwTailDataLength);
	memcpy((void*)(pDataBuffer+dwIndex), (void*)pEncryptDataBuffer, dwTailDataLength);
	dwIndex += dwTailDataLength;
	memcpy((void*)(pDataBuffer+dwIndex), (void*)&dwTailBodyLength, sizeof(dwTailBodyLength));
	dwIndex += sizeof(dwTailBodyLength);
	memcpy((void*)(pDataBuffer+dwIndex), (void*)ZeroTip, dwTipZeroCount+1);
	dwIndex += (dwTipZeroCount+1);

	if(dwIndex != dwTotalLength)
	{
		free(pEncryptDataBuffer);
		free(pDataBuffer);
		CloseHandle(hFile);
		return false;
	}
		
	//---------------------------------------------------------------------------------------------
	//write data to file end
	DWORD dwBytesWritten = 0;
	SetFilePointer(hFile,0, NULL, FILE_END);
	if(!WriteFile(hFile, pDataBuffer, dwTotalLength, &dwBytesWritten, NULL))
	{
		free(pEncryptDataBuffer);
		free(pDataBuffer);
		CloseHandle(hFile);
		return false;
	}
	else
	{
		free(pEncryptDataBuffer);
		free(pDataBuffer);
		CloseHandle(hFile);
		return true;
	}

}


//////////////////////////////////////////////////////////////
//first test whether the file has a tail,if does,cut the file to its original size
//
//////////////////////////////////////////////////////////////
bool SmartTail::CutTail(const char * lpszFilePath)
{
	HANDLE	hFile = CreateFile((TCHAR *)lpszFilePath,
							GENERIC_WRITE|GENERIC_READ,
							0,//no read or write share
							NULL,
							OPEN_EXISTING,
							NULL/*FILE_FLAG_SEQUENTIAL_SCAN*/,
							NULL);

	if(hFile == INVALID_HANDLE_VALUE)
		return false;

	__try
	{
		if(!ParseTail(hFile))
			return false;

		if(m_dwOriginalFileLength > 0)
		{

			//use file original size member which got from ParseTail()
			SetFilePointer(hFile, m_dwOriginalFileLength, NULL, FILE_BEGIN);

			if(SetEndOfFile(hFile))
				return true;
			else
				return false;

		}
	}
	__finally
	{
		CloseHandle(hFile);
	}

	return false;
}
/////////////////////////////////////////////////////////////////////////////////
//Get data in the file tail if the file really has a tail
//use the parse result;decrypt data before return it
////////////////////////////////////////////////////////////////////////////////////
bool SmartTail::GetTailData(const char * lpszFilePath,OUT byte* pDataBuf,IN OUT DWORD* pdwLength)
{
	HANDLE	hFile = CreateFile((TCHAR *)lpszFilePath,
								GENERIC_READ,
								FILE_SHARE_READ,
								NULL,
								OPEN_EXISTING,
								NULL/*FILE_FLAG_SEQUENTIAL_SCAN*/,
								NULL);

	if(hFile == INVALID_HANDLE_VALUE)
		return false;




	byte* pEncryptDataInTail = NULL;


	__try
	{	
		if(!ParseTail(hFile))
			return false;

		if(!m_bParsed || m_dwTailDataLength < 8)
			return false;

		if(*pdwLength < m_dwTailDataLength)
			return false;

		pEncryptDataInTail = (byte*)malloc(m_dwTailDataLength + 16);

		SetFilePointer(hFile, m_dwTailDataLocation, NULL, FILE_BEGIN);

		DWORD dwBytesRead = 0;
		if(!ReadFile(hFile, pEncryptDataInTail, m_dwTailDataLength, &dwBytesRead, NULL))
			return false;
		*pdwLength = m_dwTailDataLength;
		CryptData(pEncryptDataInTail, pDataBuf, pdwLength, m_FileHash, 16, false);

		return true;

	}
	__finally
	{
		if(pEncryptDataInTail != NULL)
			free(pEncryptDataInTail);

		CloseHandle(hFile);
	}


}

//////////////////////////////////////////////////////////////////////////
//encrypt or decrypt a data section by a target key
//
///////////////////////////////////////////////////////////////////////////
void SmartTail::CryptData(IN byte* pbInputData, OUT byte* pbOutputData, IN OUT DWORD* pdwDataLen, byte* pKey, DWORD dwKeyLen, bool bEncrypt)
{
	HCRYPTPROV hProv;
    HCRYPTHASH hHash;
	HCRYPTKEY hKey = NULL; 
	DWORD	dwBlockLen;
	DWORD	dwBufferLen;
	BOOL bResult = FALSE;
	PBYTE pbBuffer = NULL;

	//---------------------------------------------------------------------------------------------
    // do some prepare
    bResult = CryptAcquireContext(&hProv,
								NULL,
								NULL/*MS_ENHANCED_PROV*/,
								PROV_RSA_FULL,
								CRYPT_VERIFYCONTEXT);
	CHECK_NULL_RET(bResult);

	bResult = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CHECK_NULL_RET(bResult);

	bResult = CryptHashData(hHash, (const BYTE *)pKey, dwKeyLen, 0);
	CHECK_NULL_RET(bResult);

	bResult = CryptDeriveKey(hProv, ENCRYPT_ALGORITHM , hHash, KEYLENGTH | CRYPT_EXPORTABLE, &hKey);
	CHECK_NULL_RET(bResult);

	//-----------------------------------------------------------------
	//calculate block length and buffer length, if bEncrypt is true the buffer size will plus a ENCRYPT_BLOCK_SIZE
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

	if(ENCRYPT_BLOCK_SIZE > 1) 
    {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
    }
    else 
    {
        dwBufferLen = dwBlockLen; 
    }


	//---------------------------------------------------------------
	//Allocate memory. 
	pbBuffer = (BYTE *)malloc(dwBufferLen);
	bResult = (pbBuffer == NULL)? FALSE:TRUE;
	CHECK_NULL_RET(bResult);

	//---------------------------------------------------------------
    // In a do loop, encrypt the source data, 
    // and write to the target buffer. 
	DWORD dwSourceLen = *pdwDataLen;
	DWORD dwCryptLen = 0;
	DWORD dwLeftLen = *pdwDataLen;
	DWORD dwOutputLen = 0;
	BOOL fEOF = FALSE;
	DWORD dwCopyLen = 0;


	while(dwCryptLen < dwSourceLen)
	{
		dwLeftLen = dwSourceLen - dwCryptLen;
		if(dwLeftLen >= dwBlockLen)
		{
			dwCopyLen = dwBlockLen;
			fEOF = FALSE;
		}
		else
		{
			dwCopyLen = dwLeftLen;
			fEOF = TRUE;
		}

		memcpy(pbBuffer, pbInputData + dwCryptLen, dwCopyLen);
		dwCryptLen += dwCopyLen;
		//-----------------------------------------------------------
        // Encrypt data or Decrypt data

		if(bEncrypt)
		{        
			bResult = CryptEncrypt(	hKey, 
							NULL, 
							fEOF,
							0, 
							pbBuffer, 
							&dwCopyLen, 
							dwBufferLen);
		}
		else//decrypt
		{
			bResult = CryptDecrypt(	hKey, 
							NULL, 
							fEOF,
							0, 
							pbBuffer, 
							&dwCopyLen);
		}
		
		CHECK_NULL_RET(bResult);
		//-------------------------------------------------------------
		//copy encrypt or decrypt data to output buffer
		memcpy(pbOutputData+dwOutputLen, pbBuffer, dwCopyLen);
		dwOutputLen += dwCopyLen;
		
	}


EXIT0:

	if(bResult)
		*pdwDataLen = dwOutputLen;
	else
		*pdwDataLen = 0;

	if(hHash != 0)
	{	
		CryptDestroyHash(hHash);
	}
	if(hProv != 0)
	{
		CryptReleaseContext(hProv, 0);
	}
	if(pbBuffer != NULL)
	{
		free(pbBuffer);
	}
	return;

}