#include "cabb.h"
#include "SmartTail.h"




bool Cabbage::EnCabFile(const char* oriFile, const char* tarFile)
{
	//1 create random bytes and temp file name
	BYTE CHAOS[32];
	if(!ProduceRandomNumberCrypt(CHAOS, sizeof(CHAOS)))
		return false;

	char szTempFileName[1024];
	if(!CreateTempFileName(szTempFileName, sizeof(szTempFileName)))
		return false;

	//2 call fileencrypt() using random bytes as chaos, get tempTarFile
	if(!FileEncrypt(oriFile, szTempFileName, CHAOS, sizeof(CHAOS)))
		return false;

	//3 add chaos to tempTarFile as a smartTail
	SmartTail stl;
	stl.AddTail(szTempFileName, CHAOS, sizeof(CHAOS));

	//4 return tarFile
	return MoveFile(szTempFileName, tarFile);

}
bool Cabbage::DeCabFile(const char* oriFile, const char* tarFile)
{
	BYTE CHAOS[64];
	DWORD dwChaosLen = sizeof(CHAOS);

	//1 get tempTarFile by cutting up smartTail, get chaos and encryptFile
	SmartTail stl;
	if(!stl.GetTailData(oriFile, CHAOS, &dwChaosLen))
	{
		return false;
	}

	char szTempFileName[1024];
	if(!CreateTempFileName(szTempFileName, sizeof(szTempFileName)))
	{
		return false;
	}

	if(!CopyFile(oriFile, szTempFileName, false))
	{
		return false;
	}

	if(!stl.CutTail(szTempFileName))
	{
		return false;
	}


	//2 call FileDecrypt to recover original file

	if(!FileDecrypt(szTempFileName, tarFile, CHAOS, dwChaosLen))
	{
		return false;
	}

	DeleteFile(szTempFileName);

	return true;
}

bool Cabbage::FileCrypt(const char* oriFile, const char* tarFile, BYTE* lpChaos, DWORD dwChaosLen, bool bEncrypt)
{
#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define ENCRYPT_BLOCK_SIZE 8 


	bool bRet = true;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE; 

	HCRYPTPROV hCryptProv = NULL; 
    HCRYPTKEY hKey = NULL; 
    HCRYPTKEY hXchgKey = NULL; 
    HCRYPTHASH hHash = NULL; 

	PBYTE pbBuffer = NULL; 
    DWORD dwBlockLen; 
    DWORD dwBufferLen; 
    DWORD dwCount; 

	//---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFile(
        oriFile, 
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if(INVALID_HANDLE_VALUE == hSourceFile)
    {
		bRet = false;
		goto _EXIT_SPOT_;
    }


    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFile(
        tarFile, 
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if(INVALID_HANDLE_VALUE == hDestinationFile)
    {
		bRet = false;
		goto _EXIT_SPOT_;
	}


	//---------------------------------------------------------------
    // Get the handle to the default provider. 
    if(!CryptAcquireContext(
        &hCryptProv, 
        NULL, 
        MS_ENHANCED_PROV, 
        PROV_RSA_FULL, 
        0))
    {
		bRet = false;
		goto _EXIT_SPOT_;
    }



	//-----------------------------------------------------------
    // Create a hash object. 
    if(!CryptCreateHash(
        hCryptProv, 
        CALG_MD5, 
        0, 
        0, 
        &hHash))
    {
		bRet  = false;
		goto _EXIT_SPOT_;
	}


    //-----------------------------------------------------------
    // Hash the password. 
    if(!CryptHashData(
        hHash, 
        (BYTE *)lpChaos, 
        dwChaosLen, 
        0))
    {
		bRet  = false;
		goto _EXIT_SPOT_;
    }


    //-----------------------------------------------------------
    // Derive a session key from the hash object. 
    if(!CryptDeriveKey(
        hCryptProv, 
        ENCRYPT_ALGORITHM, 
        hHash, 
        KEYLENGTH, 
        &hKey))
    {
        bRet  = false;
		goto _EXIT_SPOT_;
    }


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
    // Allocate memory. 
    pbBuffer = (BYTE *)malloc(dwBufferLen);

	//---------------------------------------------------------------
    // In a do loop, encrypt the source file, 
    // and write to the source file. 
    bool fEOF = FALSE;
    do 
    { 
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if(!ReadFile(
            hSourceFile, 
            pbBuffer, 
            dwBlockLen, 
            &dwCount, 
            NULL))
        {
			bRet  = false;
			goto _EXIT_SPOT_;
        }

        if(dwCount < dwBlockLen)
        {
            fEOF = TRUE;
        }

		if(bEncrypt)
		{        
			//-----------------------------------------------------------
			// Encrypt data. 
			if(!CryptEncrypt(
				hKey, 
				NULL, 
				fEOF,
				0, 
				pbBuffer, 
				&dwCount, 
				dwBufferLen))
			{ 
				bRet  = false;
				goto _EXIT_SPOT_;
			} 
		}
		else
		{
			//-----------------------------------------------------------
			// Decrypt data. 
			if(!CryptDecrypt(
              hKey, 
              NULL, 
              fEOF, 
              0, 
              pbBuffer, 
              &dwCount))
			{
				bRet  = false;
				goto _EXIT_SPOT_;
			}
		}



        //-----------------------------------------------------------
        // Write the encrypted data to the destination file. 
        if(!WriteFile(
            hDestinationFile, 
            pbBuffer, 
            dwCount,
            &dwCount,
            NULL))
        { 
			bRet  = false;
			goto _EXIT_SPOT_;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while(!fEOF);

	bRet = true;

_EXIT_SPOT_:

	if(hSourceFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hSourceFile);
	}

	if(hDestinationFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
    // Free memory. 
    if(pbBuffer) 
    {
        free(pbBuffer); 
    }
     
	//---------------------------------------------------------------
    // Release the session key. 
    if(hKey)
    {
        CryptDestroyKey(hKey);
    }

    //-----------------------------------------------------------
    // Release the hash object. 
    if(hHash) 
    {
        CryptDestroyHash(hHash);
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if(hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
    }
    
	return bRet; 

}


bool Cabbage::FileEncrypt(const char* oriFile, const char* tarFile, BYTE* lpChaos, DWORD dwChaosLen)
{
	return FileCrypt(oriFile, tarFile, lpChaos, dwChaosLen, true);
}


bool Cabbage::FileDecrypt(const char* oriFile, const char* tarFile,  BYTE* lpChaos, DWORD dwChaosLen)
{
	return FileCrypt(oriFile, tarFile, lpChaos, dwChaosLen, false);
}

bool ProduceRandomNumberCrypt(BYTE* lpRandomBytes,DWORD dwSize)
{
	HCRYPTPROV   hCryptProv;
    if(!CryptAcquireContext(    
						   &hCryptProv,
						   NULL,
						   NULL,
						   PROV_RSA_FULL,
						   0)) 
    {    
        return false;
    }


    bool ret = CryptGenRandom(	hCryptProv, dwSize, (BYTE*)lpRandomBytes);

	CryptReleaseContext(hCryptProv, 0);

	return ret;
}

bool CreateTempFileName(char* szTempFileName, DWORD dwLength)
{
	char lpPathBuffer[2048];
	char szTempName[2048];

	GetTempPath(2048, lpPathBuffer); 

	GetTempFileName(lpPathBuffer, // temp file path 
        "NEW",                   // perfix  
        0,                        //  unique  name
        szTempName);              // name buffer

	DWORD dwNameLength = strlen(szTempName);

	if(dwLength <= dwNameLength)
	{
		return false;
	}
	else
	{
		memset(szTempFileName, 0, dwLength);
		memcpy(szTempFileName, szTempName, dwNameLength);
		return true;
	}

}