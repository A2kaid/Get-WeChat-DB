#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <stdio.h>
#include <iostream>
#include <process.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <Windows.h>

using namespace std;

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

#define MAX_DATA_BLOCK_SIZE 8192

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

void serve_client(void *s) {
	printf("\n\n\n创建新线程成功！\n\n\n");
	char file_name[MAX_PATH];
	unsigned char pass[MAX_PATH] = { 0 };
	char data[MAX_DATA_BLOCK_SIZE];
	int i;
	char c;
	FILE *fp;

	printf("接收密钥。。。。\n");

	for (i = 0; i < sizeof(pass); i++) {
		if (recv(*(SOCKET *)s, &c, 1, 0) != 1) {
			printf("接收失败或客户端已关闭连接\n");
			closesocket(*(SOCKET *)s);
			return;
		}
		if (c == 0) {
			break;
		}
		pass[i] = c;
	}

	for (i = 0; i < 32; i++)
	{
		printf("%x", pass[i]);
	}
	printf("\n");

	printf("接收文件名。。。。\n");
	memset((void *)file_name, 0, sizeof(file_name));
	for (i = 0; i < sizeof(file_name); i++) {
		if (recv(*(SOCKET *)s, &c, 1, 0) != 1) {
			printf("接收失败或客户端已关闭连接\n");
			closesocket(*(SOCKET *)s);
			return;
		}
		if (c == 0) {
			break;
		}
		file_name[i] = c;
	}
	if (i == sizeof(file_name)) {
		printf("文件名过长\n");
		closesocket(*(SOCKET *)s);
		return;
	}
	printf("文件名%s\n", file_name);
	fp = fopen(file_name, "wb");
	if (fp == NULL) {
		printf("无法以写方式打开文件\n");
		closesocket(*(SOCKET *)s);
		return;
	}
	printf("接收文件内容");
	memset((void *)data, 0, sizeof(data));
	for (;;) {

		i = recv(*(SOCKET *)s, data, sizeof(data), 0);
		putchar('.');
		if (i == SOCKET_ERROR) {
			printf("\n接收失败，文件可能不完整\n");
			break;
		}
		else if (i == 0) {
			printf("\n接收成功\n");
			break;
		}
		else {
			fwrite((void *)data, 1, i, fp);
		}
	}
	fclose(fp); 
	closesocket(*(SOCKET *)s);

	Decryptdb(file_name, pass);

	_endthread();
	
}

void error_exit(const char * msg, int val) {
	if (msg) { printf("%s\n\n", msg); }
	printf("使用方法：ft_server [监听端口]\n");
	printf("监听端口是可选参数，默认为8888\n\n");
	exit(val);

}

void print_socket_detail(SOCKET s) {
	struct sockaddr_in name;
	int namelen;
	namelen = sizeof(name);
	memset(&name, 0, namelen);
	getsockname(s, (struct sockaddr*)&name, &namelen);
	printf("local:%s:%d\n", inet_ntoa(name.sin_addr), ntohs(name.sin_port));
	namelen = sizeof(name);
	memset(&name, 0, namelen);
	getpeername(s, (struct sockaddr*)&name, &namelen);
	printf("peer:%s:%d\n", inet_ntoa(name.sin_addr), ntohs(name.sin_port));
}

void serve_at(u_short port) {
	WSADATA wsaData;
	SOCKET ls, as;
	static SOCKET *a;
	struct sockaddr_in addr;
	struct sockaddr_in cli_addr;
	int cli_addr_len;
	WSAStartup(0x202, &wsaData);
	ls = socket(AF_INET, SOCK_STREAM, 0);
	memset((void *)&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	addr.sin_port = htons(port);
	bind(ls, (struct sockaddr *)&addr, sizeof(addr));
	listen(ls, SOMAXCONN);
	printf("服务器已启动，监听于端口%d\n", port);
	for (;;) {
		cli_addr_len = sizeof(cli_addr);
		memset((void *)&cli_addr, 0, cli_addr_len);
		as = accept(ls, (struct sockaddr *)&cli_addr, &cli_addr_len);
		a = &as;
		printf("客户端%s:%d已连接\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
		_beginthread(serve_client, 0, (void *)a);
		Sleep(1000);
		print_socket_detail(as);
		// while(1){}
	}
	closesocket(ls);
	WSACleanup();
}

int main(int argc, char ** argv) {
	u_short port;
	if (argc == 1) {
		serve_at(8888);
	}
	else if (argc == 2) {
		port = (u_short)atoi(argv[1]);
		if (port == 0) {
			error_exit("非法的监听端口", -1);
		}
		else {
			serve_at(port);
		}
	}
	else {
		error_exit("参数错误", -1);
	}
	return 0;
}