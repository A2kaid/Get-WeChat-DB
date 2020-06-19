#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <stdio.h>
#include <iostream>
#include <windows.h>

#pragma comment(lib,"ws2_32.lib")

int winStartUp();
int client(unsigned char *pass);
void getPath(unsigned char *dbpath);