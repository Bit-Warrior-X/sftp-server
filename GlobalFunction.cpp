#include "GlobalFunction.h"

#include <time.h>
wchar_t* CharArrayToWString(char* CStr, unsigned int m_CodePage)
{
    int size = MultiByteToWideChar(m_CodePage, 0, CStr, -1, NULL, 0);
    int asize = size + 1;
    wchar_t* WStr = new wchar_t[asize];
    MultiByteToWideChar(m_CodePage, 0, CStr, -1, WStr, size);
    //outCString->Format(L"%s",WStr);
    return WStr;
}
char* CStringToCharArray(wchar_t* str, unsigned int m_CodePage)
{
    char* ptr;
    LONG len;
    len = WideCharToMultiByte(m_CodePage, 0, str, -1, NULL, 0, NULL, NULL);
    int asize = len + 1;
    ptr = new char[asize];
    memset(ptr, 0, asize);
    WideCharToMultiByte(m_CodePage, 0, str, -1, ptr, len + 1, NULL, NULL);
    return ptr;
}
string WstringTostring(wstring wtr, unsigned int m_CodePage)
{
    char* str = CStringToCharArray((wchar_t*)wtr.c_str(), m_CodePage);
    string ret = str;
    delete[] str;
    return ret;
}
wstring stringToWstring(string str, unsigned int m_CodePage)
{
    wchar_t* wtr = CharArrayToWString((char*)str.c_str(), m_CodePage);
    wstring ret = wtr;
    delete[] wtr;
    return ret;
}
SYSTEMTIME TimetToSystemTimeEx(time_t t)
{
    struct tm tmTmp;
    localtime_s(&tmTmp, &t);
    SYSTEMTIME st = { 1900 + tmTmp.tm_year,1 + tmTmp.tm_mon,tmTmp.tm_wday,
                     tmTmp.tm_mday,tmTmp.tm_hour,tmTmp.tm_min,tmTmp.tm_sec,0 };
    return st;
}
bool dirExists(const wchar_t* dirPath)
{
    DWORD ftyp = GetFileAttributes(dirPath);
    if (ftyp == INVALID_FILE_ATTRIBUTES)
        return false;  //something is wrong with your path!

    if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
        return true;   // this is a directory!

    return false;    // this is not a directory!
}