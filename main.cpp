#include "sftp_server_service.h"
#include "service_installer.h"
#include "MainSFTPServer.h"

#include <iostream>
#include <locale>
#include <codecvt>

using namespace std;

static const char usage[] =

"\n"
" SFTPService v1.0 Copyright 2023 PathSolutions, Inc.\n"
"\n"
"  usage:  %ws <options> \n"
"\n"
"  Options:\n"
"	  -l       <path>     : Output logging information to the specific text file\n"
"	  -i                  : Install service\n"
"	  -u                  : Uninstall service\n"
"\n"
"	  --help              : Displays this usage screen\n"
"\n";

static void sftp_server_usage(TCHAR* argv[])
{
    printf(usage, argv[0]);
}
extern string g_log_path;

void write_registry()
{
    HKEY hKey;
    LPCWSTR subKey = L"HKEY_CURRENT_USER\\SOFTWARE\\PathSolutionSFTPServer";
    LPCWSTR valueName = L"LogPath";
    LPCWSTR valueData = L"Hello, World!";
    DWORD dataSize = 256;
    WCHAR buffer[256];

    // Open or create the registry key
    if (RegCreateKeyEx(HKEY_CLASSES_ROOT, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        // Get the required buffer size
        int bufferSize = MultiByteToWideChar(CP_UTF8, 0, g_log_path.c_str(), -1, NULL, 0);

        // Allocate memory for the wide string
        wchar_t* wideStr = new wchar_t[bufferSize];

        // Convert the string to wide string
        MultiByteToWideChar(CP_UTF8, 0, g_log_path.c_str(), -1, wideStr, bufferSize);

        // Write the value to the registry
        if (RegSetValueEx(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(wideStr), (wcslen(wideStr) + 1) * sizeof(WCHAR)) == ERROR_SUCCESS) {
            std::cout << "Log Path written to the registry successfully." << std::endl;
        }
        else {
            std::cout << "Failed to write log path to the registry." << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "Failed to open or create the registry key." << std::endl;
    }
}

void read_log_path_registry()
{
    HKEY hKey;
    LPCWSTR subKey = L"HKEY_CURRENT_USER\\SOFTWARE\\PathSolutionSFTPServer";
    LPCWSTR valueName = L"LogPath";
    LPCWSTR valueData = L"Hello, World!";
    DWORD dataSize = 256;
    WCHAR buffer[256];

    // Open or create the registry key
    if (RegCreateKeyEx(HKEY_CLASSES_ROOT, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        // Read the value from the registry
        if (RegQueryValueEx(hKey, valueName, NULL, NULL, reinterpret_cast<LPBYTE>(buffer), &dataSize) == ERROR_SUCCESS) {
            std::wcout << "Read log path from the registry: " << buffer << std::endl;
        }
        else {
            std::cout << "Failed to read log path from the registry." << std::endl;
        }

        sftp_set_log_path(buffer);

        RegCloseKey(hKey);
    }
    else {
        std::cout << "Failed to open or create the registry key." << std::endl;
    }
}

int _tmain(int argc, TCHAR* argv[]) {
  SftpServerService service;

  char configPath[1024];
  char * homepath = NULL;
  size_t hompathsize = 0;
  _dupenv_s(&homepath, &hompathsize, "USERPROFILE");
  //printf("USERPROFILE = %s\n", homepath);

  if (homepath == NULL) {
      printf("Failed to get current user home directory\n");
      return - 1;
  }

  for (int i = 1 ; i < argc ; i ++)
  {
    if (_tcscmp(argv[i], _T("-h")) == 0 || _tcscmp(argv[i], _T("-help")) == 0 || _tcscmp(argv[i], _T("-?")) == 0) {
        sftp_server_usage(argv);
        return 0;
    }

    else if (_tcscmp(argv[i], _T("-l")) == 0) {
        if (i == argc - 1  || argv[i + 1] == NULL) {
            printf("-l requires log file name.\n");
            sftp_server_usage(argv);
            return 0;
        }
        std::wstring_convert<std::codecvt_utf8_utf16<_TCHAR>, _TCHAR> converter;
        g_log_path = converter.to_bytes(argv[i + 1]); // Convert to std::string

        write_registry();
    }

    else if (_tcscmp(argv[i], _T("-i")) == 0) {
        _tprintf(_T("Installing service\n"));
        if (!ServiceInstaller::Install(service)) {
            _tprintf(_T("Couldn't install service: %d\n"), ::GetLastError());
            return -1;
        }

        snprintf(configPath, 1024, "%s\\Config.ini", homepath);
        if (CopyFileA("Config.ini", configPath, FALSE))
        {
            printf("Install Config.ini success\n");
        }
        else {
            printf("Failed to install Config.ini\n");
            return -1;
        }

        snprintf(configPath, 1024, "%s\\ssh_host_rsa_key", homepath);
        if (CopyFileA("ssh_host_rsa_key", configPath, FALSE))
        {
            printf("Install ssh_host_rsa_key success\n");
        }
        else {
            printf("Failed to install ssh_host_rsa_key\n");
            return -1;
        }

        snprintf(configPath, 1024, "%s\\ssh_host_rsa_key.pub", homepath);
        if (CopyFileA("ssh_host_rsa_key.pub", configPath, FALSE))
        {
            printf("Install ssh_host_rsa_key.pub success\n");
        }
        else {
            printf("Failed to install ssh_host_rsa_key.pub\n");
            return -1;
        }

        _tprintf(_T("Service installed\n"));
        return 0;
    }
    else if (_tcscmp(argv[i], _T("-u")) == 0) {
        _tprintf(_T("Uninstalling service\n"));
        if (!ServiceInstaller::Uninstall(service)) {
            _tprintf(_T("Couldn't uninstall service: %d\n"), ::GetLastError());
            return -1;
        }

        _tprintf(_T("Service uninstalled\n"));
        return 0;
    }
  }

  read_log_path_registry();
  service.Run();

  return 0;
}