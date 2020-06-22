#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <stdio.h>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <Windows.h>

using namespace std;

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

#if _MSC_VER>=1900
#include "stdio.h" 
_ACRTIMP_ALT FILE* __cdecl __acrt_iob_func(unsigned);
#ifdef __cplusplus 
extern "C"
#endif 
FILE* __cdecl __iob_func(unsigned i) {
	return __acrt_iob_func(i);
}
#endif /* _MSC_VER>=1900 */



#undef _UNICODE
#define SQLITE_FILE_HEADER "SQLite format 3" 
#define IV_SIZE 16
#define HMAC_SHA1_SIZE 20
#define KEY_SIZE 32

#define SL3SIGNLEN 20


#ifndef ANDROID_WECHAT
#define DEFAULT_PAGESIZE 4096       //4048数据 + 16IV + 20 HMAC + 12
#define DEFAULT_ITER 64000
#else
#define NO_USE_HMAC_SHA1
#define DEFAULT_PAGESIZE 1024
#define DEFAULT_ITER 4000
#endif

//pc端密码是经过OllyDbg得到的32字节密钥
int Decryptdb(const char*  dbfilename, unsigned char* pass) {
	for (int i = 0; i < 0x20; i++)
	{
		printf("%02x", pass[i]);
	}

	//unsigned char pass[] = { 0xf6,0x00,0x0c,0x6c,0x7b,0xb5,0x42,0x8d,0x95,0xd5,0x91,0x35,0x6d,0x33,0x1b,0x0e,0xc9,0xce,0xf0,0xbd,0xc8,0x32,0x48,0x72,0xa2,0x35,0x5d,0xb7,0xf6,0xb0,0x32,0x28 };
	//printf("%d\n", strcmp((const char *)pass, (const char *)pas

	FILE* fpdb;
	fopen_s(&fpdb, dbfilename, "rb+");
	if (!fpdb) {
		printf("打开文件失败!");
		printf("%d", GetLastError());
		getchar();
		return 0;
	}
	fseek(fpdb, 0, SEEK_END);
	long nFileSize = ftell(fpdb);
	fseek(fpdb, 0, SEEK_SET);
	unsigned char* pDbBuffer = new unsigned char[nFileSize];
	fread(pDbBuffer, 1, nFileSize, fpdb);
	fclose(fpdb);

	unsigned char salt[16] = { 0 };
	memcpy(salt, pDbBuffer, 16);

#ifndef NO_USE_HMAC_SHA1
	unsigned char mac_salt[16] = { 0 };
	memcpy(mac_salt, salt, 16);
	for (int i = 0; i < sizeof(salt); i++) {
		mac_salt[i] ^= 0x3a;
	}
#endif

	int reserve = IV_SIZE;      //校验码长度,PC端每4096字节有48字节
#ifndef NO_USE_HMAC_SHA1
	reserve += HMAC_SHA1_SIZE;
#endif
	reserve = ((reserve % AES_BLOCK_SIZE) == 0) ? reserve : ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

	unsigned char key[KEY_SIZE] = { 0 };
	unsigned char mac_key[KEY_SIZE] = { 0 };

	OpenSSL_add_all_algorithms();
	PKCS5_PBKDF2_HMAC_SHA1((const char*)pass, 32, salt, sizeof(salt), DEFAULT_ITER, sizeof(key), key);
#ifndef NO_USE_HMAC_SHA1
	//此处源码，怀疑可能有错，pass 数组才是密码
	//PKCS5_PBKDF2_HMAC_SHA1((const char*)key, sizeof(key), mac_salt, sizeof(mac_salt), 2, sizeof(mac_key), mac_key);
	PKCS5_PBKDF2_HMAC_SHA1((const char*)key, sizeof(key), mac_salt, sizeof(mac_salt), 2, sizeof(mac_key), mac_key);
#endif

	unsigned char* pTemp = pDbBuffer;
	unsigned char pDecryptPerPageBuffer[DEFAULT_PAGESIZE];
	int nPage = 1;
	int offset = 16;
	while (pTemp < pDbBuffer + nFileSize) {
		printf("解密数据页:%d/%d \n", nPage, nFileSize / DEFAULT_PAGESIZE);

#ifndef NO_USE_HMAC_SHA1
		unsigned char hash_mac[HMAC_SHA1_SIZE] = { 0 };
		unsigned int hash_len = 0;
		HMAC_CTX hctx;
		HMAC_CTX_init(&hctx);
		HMAC_Init_ex(&hctx, mac_key, sizeof(mac_key), EVP_sha1(), NULL);
		HMAC_Update(&hctx, pTemp + offset, DEFAULT_PAGESIZE - reserve - offset + IV_SIZE);
		HMAC_Update(&hctx, (const unsigned char*)& nPage, sizeof(nPage));
		HMAC_Final(&hctx, hash_mac, &hash_len);
		HMAC_CTX_cleanup(&hctx);
		if (0 != memcmp(hash_mac, pTemp + DEFAULT_PAGESIZE - reserve + IV_SIZE, sizeof(hash_mac))) {
			//printf("\n 哈希值错误! \n");
			//getchar();
			//return 0;
		}
#endif
		//
		if (nPage == 1) {
			memcpy(pDecryptPerPageBuffer, SQLITE_FILE_HEADER, offset);
		}

		EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(ectx, EVP_get_cipherbyname("aes-256-cbc"), NULL, NULL, NULL, 0);
		EVP_CIPHER_CTX_set_padding(ectx, 0);
		EVP_CipherInit_ex(ectx, NULL, NULL, key, pTemp + (DEFAULT_PAGESIZE - reserve), 0);

		int nDecryptLen = 0;
		int nTotal = 0;
		EVP_CipherUpdate(ectx, pDecryptPerPageBuffer + offset, &nDecryptLen, pTemp + offset, DEFAULT_PAGESIZE - reserve - offset);
		nTotal = nDecryptLen;
		EVP_CipherFinal_ex(ectx, pDecryptPerPageBuffer + offset + nDecryptLen, &nDecryptLen);
		nTotal += nDecryptLen;
		EVP_CIPHER_CTX_free(ectx);

		memcpy(pDecryptPerPageBuffer + DEFAULT_PAGESIZE - reserve, pTemp + DEFAULT_PAGESIZE - reserve, reserve);
		char decFile[32] = "dec_MSG0.db";

		FILE * fp;
		fopen_s(&fp, decFile, "ab+");
		{
			fwrite(pDecryptPerPageBuffer, 1, DEFAULT_PAGESIZE, fp);
			fclose(fp);
		}

		nPage++;
		offset = 0;
		pTemp += DEFAULT_PAGESIZE;
	}
	printf("\n 解密成功! \n");
	return 0;
}

int main()
{
	WORD wVersion = MAKEWORD(2, 2);
	WSADATA wsaData;

	if (WSAStartup(wVersion, &wsaData) != 0)
	{
		cout << "WSAStartup failed with error " << WSAGetLastError() << endl;
		return 0;
	}

	SOCKET sServer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sockaddr_in addrSer;
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(5555);
	addrSer.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	bind(sServer, (sockaddr*)&addrSer, sizeof(addrSer));

	sockaddr_in addrClient;
	int lenght = sizeof(addrClient);
	char recvBuf[BUFSIZ] = { 0 };
	int rev = 0;
	int i = 0;

	while (true)
	{
		char sendData[BUFSIZ] = "hello!\n";
		char beginData[BUFSIZ] = "Begin\n";
		char overData[BUFSIZ] = "Over\n";
		char okBuf[BUFSIZ] = "OK\n";
		char filename[BUFSIZ] = { 0 };
		char pass[BUFSIZ] = { 0 };
		sprintf(filename, "%d.db", i++);

		FILE* fp = NULL;
		sendto(sServer, sendData, BUFSIZ, 0, (sockaddr*)&addrClient, lenght);
		recvfrom(sServer, recvBuf, BUFSIZ, 0, (sockaddr*)&addrClient, &lenght);
		if (strcmp(recvBuf, beginData) == 0)
		{
			cout << "ready to receive file: \n";
			fp = fopen(filename, "wb");
			if (NULL == fp)
			{
				cout << "cannot write file!" << endl;
				continue;
			}
		}

		recvfrom(sServer, pass, BUFSIZ, 0, (sockaddr*)&addrClient, &lenght);




		while ((rev = recvfrom(sServer, recvBuf, BUFSIZ, 0, (sockaddr*)&addrClient, &lenght)) > 0)
		{
			//cout << "#";
			if (strcmp(overData, recvBuf) == 0)
			{
				cout << "recieve successful!" << endl;
				fclose(fp);
				sendto(sServer, okBuf, BUFSIZ, 0, (sockaddr*)&addrClient, lenght);
				Decryptdb(filename, (unsigned char *)pass);
				break;
			}
			if (fwrite(recvBuf, 1, rev, fp) < 0)
			{
				cout << "write failed!" << endl;
			}
		}

		if (rev < 0 || strcmp(overData, recvBuf) != 0)
		{
			cout << "transfer failed!";
			fclose(fp);
			remove(filename);
		}


	}
	closesocket(sServer);
	WSACleanup();
	return 0;
}