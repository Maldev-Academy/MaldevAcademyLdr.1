// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#include "CTAES.h"

#define		KEY_SIZE	0x20
#define		IV_SIZE		0x10
#define		NEW_NAME	"Payload.ctaes"

#define ALLOC(SIZE)			LocalAlloc(LPTR, (SIZE_T)SIZE)
#define FREE(BUFF)			LocalFree((LPVOID)BUFF)
#define REALLOC(BUFF, SIZE)		LocalReAlloc(BUFF, SIZE,  LMEM_MOVEABLE | LMEM_ZEROINIT)

//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\

VOID PrintHexVar(IN PCSTR sVarName, IN PBYTE pBuffer, IN SIZE_T sBufferSize) {

	printf("\t<i> %s : [ ", sVarName);
	for (DWORD i = 0; i < sBufferSize; i++)
		printf("%02X ", pBuffer[i]);
	printf("]\n");

}

//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\


BOOL PaddPayload(IN OUT PBYTE* pRawPayloadBuffer, IN OUT SIZE_T* sRawPayloadSize) {
	
	// If payload size is not multiple of 16
	if (*sRawPayloadSize % 0x10 != 0) {

		printf("[-] Payload Size Is Not Multiple of 16, Padding ... ");

		// Calculate the new size that is multiple of 16, then allocate a new buffer 
		SIZE_T	PaddedPayloadSize	= *sRawPayloadSize + 0x10 - (*sRawPayloadSize % 0x10);
		PBYTE	PaddedPayload		= NULL;
		
		if (!(PaddedPayload = (PBYTE)ALLOC(PaddedPayloadSize)))
			return FALSE;

		// Copy the payload to the new allocated buffer
		RtlCopyMemory(PaddedPayload, *pRawPayloadBuffer, *sRawPayloadSize);
	
		// Free older buffer
		FREE(*pRawPayloadBuffer);
		
		// Save the new values. The payload now is padded with 0x00 bytes 
		*pRawPayloadBuffer	= PaddedPayload;
		*sRawPayloadSize	= PaddedPayloadSize;

		printf("[+] DONE \n\t<i> New Payload Size : %d\n\t<i> Buffer Holding Payload : 0x%p\n", PaddedPayloadSize, PaddedPayload);

	}

	return TRUE;
}


//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\


BOOL AesEncryptPayload(IN PBYTE pRawPayloadBuffer, IN SIZE_T sRawPayloadSize, OUT PBYTE* ppEncPayloadBuffer, OUT SIZE_T* psEncPayloadSize, OUT PBYTE pKey, OUT PBYTE pIv) {

	// Parameters check
	if (!pRawPayloadBuffer || !sRawPayloadSize)
		return FALSE;
	if (!ppEncPayloadBuffer || !psEncPayloadSize || !pKey || !pIv)
		return FALSE;

	AES256_CBC_ctx	AesCtx = { 0 };
	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));

	printf("[i] Generating AES Key and IV:\n");

	// SEED 1
	srand(GetTickCount64());
	// Generating the AES 32-bytes key
	for (DWORD i = 0; i < KEY_SIZE; i++)
		(BYTE)pKey[i] = (BYTE)(rand() % 0xFF);
	PrintHexVar("AES KEY", pKey, KEY_SIZE);

	// SEED 2
	srand(GetTickCount64() * rand());
	// Generating the AES 16-bytes Iv
	for (DWORD i = 0; i < IV_SIZE; i++)
		(BYTE)pIv[i] = (BYTE)(rand() % 0xFF);
	PrintHexVar("AES IV ", pIv, IV_SIZE);


	// Padd the payload
	if (PaddPayload(&pRawPayloadBuffer, &sRawPayloadSize)) {

		// Save the new padded payload size
		*psEncPayloadSize = sRawPayloadSize;

		// Encrypt the payload
		AES256_CBC_init(&AesCtx, pKey, pIv);
		if (!AES256_CBC_encrypt(&AesCtx, pRawPayloadBuffer, sRawPayloadSize, ppEncPayloadBuffer)) {
			return FALSE;
		}

		return TRUE;
	}

	// Coundnt padd the payload
	return FALSE;
}


//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\


BOOL ReadPayloadFile(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE	hFile			= INVALID_HANDLE_VALUE;
	PBYTE	pTmpReadBuffer		= NULL;
	DWORD	dwFileSize		= NULL,
		dwNumberOfBytesRead 	= NULL;

	if (!pdwFileSize || !ppFileBuffer)
		return FALSE;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("\t[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!(pTmpReadBuffer = ALLOC(dwFileSize))) {
		printf("\t[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pTmpReadBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile Failed With Error: %d \n", GetLastError());
		printf("\t[i] ReadFile Read %d Of %d Bytes \n", dwNumberOfBytesRead, dwFileSize);
		goto _FUNC_CLEANUP;
	}

	*ppFileBuffer	= pTmpReadBuffer;
	*pdwFileSize	= dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pTmpReadBuffer && !*ppFileBuffer)
		FREE(pTmpReadBuffer);
	return *ppFileBuffer == NULL ? FALSE : TRUE;
}


//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\


BOOL WritePayloadFile(IN PBYTE pFileBuffer, IN DWORD dwFileSize) {

	HANDLE	hFile			= INVALID_HANDLE_VALUE;
	DWORD	dwNumberOfBytesWritten	= 0x00;
	
	if (!pFileBuffer || !dwFileSize)
		return FALSE;

	if ((hFile = CreateFileA(NEW_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("\t[!] WriteFile Failed With Error: %d \n", GetLastError());
		printf("\t[i] WriteFile Wrote %d Of %d Bytes \n", dwNumberOfBytesWritten, dwFileSize);
		goto _FUNC_CLEANUP;
	}

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwNumberOfBytesWritten == dwFileSize ? TRUE : FALSE;
}


//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\


int main(int argc, char* argv[]) {
	
	PBYTE	pPlainText		= NULL,
		pCipherText		= NULL,
		pCipherTextWithConfig	= NULL;
	SIZE_T	sPlainTextSize		= NULL,
		sCipherTextSize		= NULL;

	BYTE 	pAesKey	[KEY_SIZE]	= { 0 };
	BYTE 	pAesIv	[IV_SIZE]	= { 0 };


	if (argc != 2) {
		printf("[!] Please Input Payload File Name To Encrypt\n");
		return -1;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
	printf("[i] Reading %s From The Disk ... ", argv[1]);
	if (!ReadPayloadFile(argv[1], &pPlainText, &sPlainTextSize)) {
		return -1;
	}
	printf("[+] DONE\n");

	if (!AesEncryptPayload(pPlainText, sPlainTextSize, &pCipherText, &sCipherTextSize, pAesKey, pAesIv)) {
		return -1;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	if (!(pCipherTextWithConfig = REALLOC(pCipherText, (sCipherTextSize + KEY_SIZE + IV_SIZE)))) {
		printf("[!] LocalReAlloc Failed With Error: %d \n", GetLastError());
		return -1;
	}

	memcpy((pCipherTextWithConfig + sCipherTextSize),			pAesKey,			KEY_SIZE);
	memcpy((pCipherTextWithConfig + (sCipherTextSize + KEY_SIZE)),		pAesIv,				IV_SIZE);
	
	printf("[i] Final Payload Size: %d\n", (sCipherTextSize + KEY_SIZE + IV_SIZE));

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	printf("[i] Writing \"%s\" To The Disk ... ", NEW_NAME);
	if (!WritePayloadFile(pCipherTextWithConfig, (sCipherTextSize + KEY_SIZE + IV_SIZE))) {
		return -1;
	}

	printf("[+] DONE \n");
	printf("[*] The Payload Is Ready To Go!\n");
	FREE(pCipherTextWithConfig);
	return 0;
}




