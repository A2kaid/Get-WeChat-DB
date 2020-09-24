#pragma once
#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <direct.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <string>
#include <strstream>
#include <list>
#include <Psapi.h>  
#pragma comment (lib,"Psapi.lib")  
#pragma comment(lib, "Version.lib")

using namespace std;
const string wxVersoin1 = "2.9.0.123";
const string wxVersoin2 = "2.9.0.112";
const string wxVersoin3 = "2.9.5.56";

#define version1 0x16B4D50
#define version2 0x16B4C70
#define version3 0x17744A8

#define wxid_addr3 0x1774054
#define wxname_addr3 0x17740CC

#define wxid_addr2 0x16B4834
#define wxname_addr2 0x16B48AC
//#define wxid_addr1 0x16B4914
//#define wxname_addr1 0x16B498C


DWORD GetProcessIDByName(const char* pName);
PVOID GetProcessImageBase(DWORD dwProcessId, const char* dllName);
DWORD IsWxVersionValid(WCHAR *VersionFilePath);
int GetdbKey(unsigned char *databasekey, unsigned char *wxid);