#include <stdio.h>     
#include <windows.h>  
#include "dirent.h"
#include "GlobalFunction.h"
static HANDLE hFind;

DIR* opendir(const wchar_t* name)
{
    DIR* dir;
    WIN32_FIND_DATA FindData;
    wchar_t namebuf[512];
    int n = (int)wcslen(name);
    if(n <= 0)
        return 0;
    int n1 = n - 1;
    if(name[n1]== '\\'|| name[n1] == '/')
        swprintf_s(namebuf, L"%s*.*", name);
    else
        swprintf_s(namebuf, L"%s/*.*", name);

    hFind = FindFirstFile(namebuf, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("FindFirstFile failed (%d)\n", GetLastError());
        return 0;
    }

    dir = (DIR*)malloc(sizeof(DIR));
    if (!dir)
    {
        printf("DIR memory allocate fail\n");
        return 0;
    }

    memset(dir, 0, sizeof(DIR));
    dir->dd_fd = 0;   // simulate return  

    return dir;
}

//struct dirent* readdir(DIR* d)
//{
//    int i;
//    static struct dirent dirent;
//    BOOL bf;
//    WIN32_FIND_DATA FileData;
//    if (!d)
//    {
//        return 0;
//    }
//
//    bf = FindNextFile(hFind, &FileData);
//    //fail or end  
//    if (!bf)
//    {
//        return 0;
//    }
//
//    for (i = 0; i < 256; i++)
//    {
//        dirent.d_name[i] = FileData.cFileName[i];
//        if (FileData.cFileName[i] == '\0') break;
//    }
//    dirent.d_reclen = i;
//    dirent.d_reclen = FileData.nFileSizeLow;
//
//    //check there is file or directory  
//    if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//    {
//        dirent.d_type = 2;
//    }
//    else
//    {
//        dirent.d_type = 1;
//    }
//
//
//    return (&dirent);
//}

struct dirent* readdir(DIR* d)
{
    int i;

    BOOL bf;
    WIN32_FIND_DATA FileData;
    if (!d)
    {
        return 0;
    }

    bf = FindNextFile(hFind, &FileData);
    //fail or end  
    if (!bf)
    {
        return 0;
    }

    char* m_FileNameA = CStringToCharArray(FileData.cFileName,CP_UTF8);
    struct dirent* dirent = (struct dirent*)malloc(sizeof(struct dirent) + 256);

    for (i = 0; i < 256; i++)
    {
        dirent->d_name[i] = m_FileNameA[i];
        if (m_FileNameA[i] == '\0') break;
    }
    dirent->d_reclen = i;
    dirent->d_reclen = (unsigned short)FileData.nFileSizeLow;
    delete[] m_FileNameA;
    //check there is file or directory  
    if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        dirent->d_type = 2;
    }
    else
    {
        dirent->d_type = 1;
    }

    return dirent;
}
int closedir(DIR* d)
{
    if (!d) return -1;
    hFind = 0;
    free(d);
    return 0;
}