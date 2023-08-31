#pragma once
#include <string>
#include <windows.h>
using namespace std;

wchar_t* CharArrayToWString(char* CStr, unsigned int m_CodePage);
char* CStringToCharArray(wchar_t* str, unsigned int m_CodePage);
string WstringTostring(wstring wtr, unsigned int m_CodePage);
wstring stringToWstring(string str, unsigned int m_CodePage);
SYSTEMTIME TimetToSystemTimeEx(time_t t);
bool dirExists(const wchar_t* dirPath);