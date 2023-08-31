#include "MainSFTPServer.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/bind.h>

#define WITH_SERVER 1
#include <libssh/sftp.h>
#include <libssh/session.h>

#include <stdio.h>
#include <windows.h>
#include <string>
#include <time.h>
#include <io.h>
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>
#include "dirent.h"
#include <direct.h>
#include "GlobalFunction.h"
#include <chrono>
#include <thread>


using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;
using namespace std;

//#pragma comment(linker, "/subsystem:console /entry:WinMainCRTStartup")

#define MAX_HANDLES 20 /**< Maximum handles */
#define NUM_ENTRIES_PER_PACKET 50 /**< Maximum entries per packet for readdir */


enum
{
	DIR_HANDLE,
	FILE_HANDLE
};

struct handle_table_entry
{
	int type;         /**< Handle type */
	void* handle;     /**< Handle */
	void* session_id; /**< Session ID */
	char* path;       /**< Path */
};

bool mainLoop(ssh_bind sshbind);
char* readdir_long_name(char* z_file_name, struct stat* z_st, char* z_long_name);
static void init_handle_table(void);
static int add_handle(int z_type, void* z_handle, const char* z_path, void* z_session_id);
static char* get_handle_path(void* z_handle);
static int close_handle(void* z_handle);
static int errno_to_ssh_status(int z_errno);
static int check_password(const char* z_user, const char* z_password);
static int check_publickey(const char* z_user, ssh_key z_public/*, ssh_publickey_state_e z_state*/);
static int authenticate(ssh_session z_session);
static ssh_channel open_channel(ssh_session z_session);
static int sftp_subsystem_request(ssh_session z_session);
static void process_sftp_commands(sftp_session z_sftp_sn);
static void clear_filexfer_attrib(struct sftp_attributes_struct* z_attr);
static void stat_to_filexfer_attrib(const struct stat* z_st, struct sftp_attributes_struct* z_attr);
static int realpath(const char* path, string& long_path);
static int process_realpath(sftp_client_message z_client_message);
static int process_opendir(sftp_client_message z_client_message);
static int process_readdir(sftp_client_message z_client_message);
static int process_close(sftp_client_message z_client_message);
static int process_stat(sftp_client_message z_client_message);
static int process_open(sftp_client_message z_client_message);
static int process_read(sftp_client_message z_client_message, ULONGLONG& pSend, time_t& pStart);
static int process_write(sftp_client_message z_client_message);
static int process_fstat(sftp_client_message z_client_message);
static int process_lstat(sftp_client_message z_client_message);
static int process_setstat(sftp_client_message z_client_message);
static int process_remove(sftp_client_message z_client_message);
static int process_rename(sftp_client_message z_client_message);
static int process_mkdir(sftp_client_message z_client_message);
static int process_rmdir(sftp_client_message z_client_message);
static DWORD WINAPI Thread_sftp_server(LPVOID lpParam);

void terminate_all_client_thread();

string g_user_name = "admin";
string g_password = "admin";
wstring g_rootpath = L"";// L"D:/123";
string g_rsakey = "ssh_host_rsa_key";
string g_rsapubkey = "ssh_host_rsa_key.pub";
string g_log_path = "sftp-log.txt";
//string g_critical = "sftp-critical.txt";
CRITICAL_SECTION cs;
HANDLE hMutex;
static struct handle_table_entry s_handle_table[MAX_HANDLES];

ULONGLONG m_Bandwidth = (50 * 0.125 * 1024 * 1024);
int g_stop_server = 0;

int sftp_set_log_path(wchar_t * str)
{
	//FILE* file_critical = NULL;
	//fopen_s(&file_critical, g_critical.c_str(), "a");
	//if (file_critical == NULL) {

	//	perror("Error opening file");
	//	return 0;
	//}


	// Get the required buffer size
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);

	// Allocate memory for the multi-byte string
	char* multiByteStr = new char[bufferSize];

	// Convert the wide string to multi-byte string
	WideCharToMultiByte(CP_UTF8, 0, str, -1, multiByteStr, bufferSize, NULL, NULL);

	// Use the multi-byte string
	std::string stringstr(multiByteStr);
	g_log_path = stringstr;
	// Free the allocated memory
	delete[] multiByteStr;


	//fprintf(file_critical, "%s\n", g_log_path.c_str());
	//
	//fclose(file_critical);
	return 0;
}

void appendToLogFile(const char* logMessage, const char* functionName) {
	time_t currentTime = time(NULL);
	struct tm timeInfo;
	localtime_s(&timeInfo, &currentTime);
	char timeString[20];
	strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", &timeInfo);

	FILE* file = NULL;
	fopen_s(&file, g_log_path.c_str(), "a");
	if (file == NULL) {

		//FILE* file_critical = NULL;
		//fopen_s(&file_critical, g_critical.c_str(), "a");
		//if (file_critical == NULL) {

		//	perror("Error opening file");
		//	return;
		//}

		//fprintf(file_critical, "[%s] %s: Error opening file %s\n", timeString, __func__, g_log_path.c_str());
		//fclose(file_critical);

		return;
	}

	fprintf(file, "[%s] %s: %s\n", timeString, functionName, logMessage);
	fclose(file);
}

int file_get_line(FILE* file_stream, char* str, size_t len)
{
	char   c;
	size_t l;
	char* s = str;

	if (!len)
		return 0;

	l = len;

	while (l && (c = fgetc(file_stream)) && !ferror(file_stream) && c != EOF && c != '\n') {
		if (c != '\r') {
			*(s++) = c;
			l--;
		}
	}

	if (l > 0) {
		// We need one more character
		// for trailing '\0'.
		*s = '\0';
		return (int)(s - str);
	}
	else
		// buffer overran.
		return -1;
}

static int get_key_data(char* buf, char* key, char* data, char deli)
{
	char* p, * b, * e, * k, * d;
	b = buf;
	k = key;
	d = data;

	p = strchr(buf, deli);
	if (!p) p = strchr(buf, ':');

	if (p) {

		e = p - 1;

		// get key
		while (b <= e) {
			if (*b != ' ' && *b != '\t')
				*(k++) = *b;
			b++;
		};
		*k = '\0';

		p++;

		// get data
		while (*p) {
			if (*p == '#') break;
			if (*p != ' ' && *p != '\t')
				*(d++) = *p;
			p++;
		};
		if (*(d - 1) == ';') d--;

		*d = '\0';

	}
	else {
		key[0] = '\0';
		data[0] = '\0';
		return -1;
	}
	return 0;
}

static int load_config() {
	FILE* fd = NULL;
	char buf[512], key[256], data[1024];
	char log[1024];
	int flag = 0;

	char configPath[1024];
	char* homepath = NULL;
	size_t hompathsize = 0;
	_dupenv_s(&homepath, &hompathsize, "USERPROFILE");
	//printf("USERPROFILE = %s\n", homepath);

	if (homepath == NULL) {
		printf("Failed to get current user home directory\n");
		return -1;
	}

	snprintf(configPath, 1024, "%s\\Config.ini", homepath);

	fopen_s(&fd, configPath, "r");
	if (fd == NULL) {
		printf("Config.ini file not found\n");
		return -1;
	}

	while (!feof(fd) && file_get_line(fd, buf, sizeof(buf)) >= 0) {
		if (buf[0] == '#') continue;
		if (get_key_data(buf, key, data, '='))
			continue;
		if (!strcasecmp(key, "RootPath")) {
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			g_rootpath = converter.from_bytes(data);
			flag |= 0x00001;
		}
		else if (!strcasecmp(key, "User")) {
			g_user_name = std::string(data);
			flag |= 0x00010;
		}
		else if (!strcasecmp(key, "Password")) {
			g_password = std::string(data);
			flag |= 0x00100;
		}
		/*else if (!strcasecmp(key, "RSAKey")) {
			g_rsakey = std::string(data);
			flag |= 0x01000;
		}
		else if (!strcasecmp(key, "RSAPubKey")) {
			g_rsapubkey = std::string(data);
			flag |= 0x10000;
		}*/
	}

	snprintf(configPath, 1024, "%s\\ssh_host_rsa_key", homepath);
	g_rsakey = std::string(configPath);
	flag |= 0x01000;

	snprintf(configPath, 1024, "%s\\ssh_host_rsa_key.pub", homepath);
	g_rsapubkey = std::string(configPath);
	flag |= 0x10000;

	if (flag == 0x11111)
		return 0;

	snprintf(log, 1024, "Missing one or more parameters. Please check RootPath, User, Password");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	return -1;
}

ssh_bind _sshbind = NULL;
HANDLE hamin_thread = NULL;

static DWORD WINAPI process_server_thread(LPVOID lpParam)
{
	int ret = SSH_ERROR;
	char log[1024];
	g_stop_server = 0;
	do
	{
		init_handle_table();

		if ((_sshbind = ssh_bind_new()) == NULL)
		{
			break;
		}

		if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "22") < 0)
			break;
		//ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_HOSTKEY, "dsap.txt");
		//if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_DSAKEY, "dsa.txt") < 0)
		if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_RSAKEY, /*KEYS_FOLDER*/ /*"rsa.txt"*/g_rsakey.c_str()) < 0)
			break;
		if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3") < 0)
			break;

		if (ssh_bind_listen(_sshbind) < 0)
		{
			//LOG(XM_ERR) << "Error listening to socket: " << ssh_get_error(_sshbind);
			//std::cout << "debug purpose" << std::endl;

			snprintf(log, 1024, "Error listening to socket: %s", ssh_get_error(_sshbind));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}
		ret = SSH_OK;

		snprintf(log, 1024, "Jump to mainLoop");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

		mainLoop(_sshbind);

		snprintf(log, 1024, "Finished to mainLoop");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

	} while (g_stop_server == 0);
	return 0;
}

int sftp_server_start()
{
	int ret = SSH_ERROR;
	ssh_init();
	char log[1024];

	if (load_config() < 0)
	{
		snprintf(log, 1024, "Load config file failed");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);
		return -1;
	}
	
	snprintf(log, 1024, "SFTP Server Started");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);


	DWORD ThreadID;
	//InitializeCriticalSection(&cs);
	hamin_thread = CreateThread(NULL, 0, process_server_thread, NULL, 0, &ThreadID);


#if 0
	g_stop_server = 0;

	do
	{
		init_handle_table();

		if ((_sshbind = ssh_bind_new()) == NULL)
		{
			break;
		}

		if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "22") < 0)
			break;
		//ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_HOSTKEY, "dsap.txt");
		//if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_DSAKEY, "dsa.txt") < 0)
		if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_RSAKEY, /*KEYS_FOLDER*/ /*"rsa.txt"*/g_rsakey.c_str()) < 0)
			break;
		if (ssh_bind_options_set(_sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3") < 0)
			break;

		if (ssh_bind_listen(_sshbind) < 0)
		{
			//LOG(XM_ERR) << "Error listening to socket: " << ssh_get_error(_sshbind);
			//std::cout << "debug purpose" << std::endl;

			snprintf(log, 1024, "Error listening to socket: %s", ssh_get_error(_sshbind));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}
		ret = SSH_OK;

		snprintf(log, 1024, "Jump to mainLoop");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

		mainLoop(_sshbind);

		snprintf(log, 1024, "Finished to mainLoop");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

	} while (g_stop_server == 0); 
#endif

	return ret;
}


int sftp_server_stop()
{
	char log[1024];
	snprintf(log, 1024, "Stopping sftpserver");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);
	
	g_stop_server = 1;

	terminate_all_client_thread();
	TerminateThread(hamin_thread, 0);
	CloseHandle(hamin_thread);

	return 0;
}

#if 0
int sftp_server_stop()
{
	char log[1024];
	snprintf(log, 1024, "Stopping sftpserver");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);
	
	DWORD pid = GetCurrentProcessId();
	snprintf(log, 1024, "Current Process ID: %lu\n", pid);
	appendToLogFile(log, __func__);

	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProcess == NULL) {
		snprintf(log, 1024, "Failed to open process. Error code: %lu\n", GetLastError());
		appendToLogFile(log, __func__);
		return 1;
	}

	if (TerminateProcess(hProcess, 0)) {
		snprintf(log, 1024, "Process with PID %lu terminated successfully.\n", pid);
		appendToLogFile(log, __func__);
	}
	else {
		snprintf(log, 1024, "Failed to terminate process. Error code: %lu\n", GetLastError());
		appendToLogFile(log, __func__);
	}

	CloseHandle(hProcess);

	//g_stop_server = 1;
	//_close(_sshbind->bindfd);

	return 0;
}
#endif

int sftp_server_release()
{
	char log[1024];
	ssh_bind_free(_sshbind);

	if (ssh_finalize() < 0)
	{
		snprintf(log, 1024, "SSH finalize failed");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);
	}

	snprintf(log, 1024, "Stopped sftpserver");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	return 0;
}


int client_cnt = 0;
#define MAX_CLIENT_NUM 8192
HANDLE client_handle_list[MAX_CLIENT_NUM];

bool mainLoop(ssh_bind sshbind)
{
	bool ret = false;
	char log[1024];
	while (g_stop_server == 0)
	{
		//int r;
		ssh_session session = ssh_new();
		if (session == NULL)
		{
			snprintf(log, 1024, "Error ssh_new");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			continue;
		}
		//LOG(XM_DEBUG) << "before accept";
		snprintf(log, 1024, "SFTP Server is waiting for new conneciton ...");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

		snprintf(log, 1024, "binding new accept ....");
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

		if (ssh_bind_accept(sshbind, session) == SSH_OK)
		{
			//LOG(XM_DEBUG) << "after accept";
			//SSH_LOG(SSH_LOG_NONE, "after accept");
			snprintf(log, 1024, "[%s] is accpeted", session->peer_address);
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);

			DWORD ThreadID;
			InitializeCriticalSection(&cs);
			HANDLE handle; 
			handle = CreateThread(NULL, 0, Thread_sftp_server, session, 0, &ThreadID);
			client_handle_list[client_cnt] = handle;
			client_cnt = (client_cnt++) % MAX_CLIENT_NUM;
			DeleteCriticalSection(&cs);

			//if (handle)
			//	CloseHandle(handle);
		}
		else
		{
			snprintf(log, 1024, "[%s] is failed to accpet", session->peer_address);
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);

			snprintf(log, 1024, "error accepting a connection : %s", ssh_get_error(sshbind));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);

		}
	}
	return ret;
}

void terminate_all_client_thread()
{
	for (int i = 0; i < client_cnt; i++)
	{
		TerminateThread(client_handle_list[i], 0);
		CloseHandle(client_handle_list[i]);
	}
}

char* readdir_long_name(char* z_file_name, struct stat* z_st, char* z_long_name)
{
	char tmpbuf[256];
	char time[50];
	char* ptr = z_long_name;
	int mode = z_st->st_mode;

	*ptr = '\0';

	switch (mode & S_IFMT)
	{
	case S_IFDIR:
	{
		*ptr++ = 'd';
		break;
	}
	default:
	{
		*ptr++ = '-';
		break;
	}
	}
	/* user */
	if (mode & 0400)
	{
		*ptr++ = 'r';
	}
	else
	{
		*ptr++ = '-';
	}
	if (mode & 0200)
	{
		*ptr++ = 'w';
	}
	else
	{
		*ptr++ = '-';
	}
	if (mode & 0100)
	{
		//if (mode & S_ISUID)
		//{
		//    *ptr++ = 's';
		//}
		//else
		//{
		*ptr++ = 'x';
		//}
	}
	else
	{
		*ptr++ = '-';
	}
	/* group */
	if (mode & 040)
	{
		*ptr++ = 'r';
	}
	else
	{
		*ptr++ = '-';
	}
	if (mode & 020)
	{
		*ptr++ = 'w';
	}
	else
	{
		*ptr++ = '-';
	}
	if (mode & 010)
	{
		*ptr++ = 'x';
	}
	else
	{
		*ptr++ = '-';
	}
	/* other */
	if (mode & 04)
	{
		*ptr++ = 'r';
	}
	else
	{
		*ptr++ = '-';
	}
	if (mode & 02)
	{
		*ptr++ = 'w';
	}
	else
	{
		*ptr++ = '-';
	}
	if (mode & 01)
	{
		*ptr++ = 'x';
	}
	else
	{
		*ptr++ = '-';
	}
	*ptr++ = ' ';
	*ptr = '\0';

	snprintf(tmpbuf, sizeof(tmpbuf), "%3d %d %d %d", (int)z_st->st_nlink,
		(int)z_st->st_uid, (int)z_st->st_gid, (int)z_st->st_size);
	strcat_s(z_long_name, 256, tmpbuf);

	ctime_s(time, 50, &z_st->st_mtime);
	if (ptr = strchr(time, '\n'))
	{
		*ptr = '\0';
	}
	snprintf(tmpbuf, sizeof(tmpbuf), " %s %s", time + 4, z_file_name);
	strcat_s(z_long_name, 256, tmpbuf);

	return z_long_name;
}
static void init_handle_table(void)
{
	hMutex = CreateMutex(NULL, false, L"Mysftp");

	for (int i = 0; i < MAX_HANDLES; i++)
	{
		s_handle_table[i].type = DIR_HANDLE;
		s_handle_table[i].handle = NULL;
		s_handle_table[i].session_id = NULL;
		s_handle_table[i].path = NULL;
	}
}

static int add_handle(int z_type, void* z_handle, const char* z_path, void* z_session_id)
{
	int ret = SSH_ERROR;

	if (z_handle != NULL)
	{
		WaitForSingleObject(hMutex, INFINITE);

		for (int i = 0; i < MAX_HANDLES; i++)
		{
			if (s_handle_table[i].handle == NULL)
			{
				s_handle_table[i].type = z_type;
				s_handle_table[i].handle = z_handle;
				size_t alen = (strlen(z_path) + 1) * sizeof(char);
				s_handle_table[i].path = (char*)malloc(alen);
				strcpy_s(s_handle_table[i].path, alen, z_path);
				s_handle_table[i].session_id = z_session_id;
				ret = SSH_OK;
				break;
			}
		}

		ReleaseMutex(hMutex);
	}

	return(ret);
}
static char* get_handle_path(void* z_handle)
{
	char* ret = NULL;

	if (z_handle != NULL)
	{
		WaitForSingleObject(hMutex, INFINITE);

		for (int i = 0; i < MAX_HANDLES; i++)
		{
			if (s_handle_table[i].handle == z_handle)
			{
				ret = s_handle_table[i].path;
				break;
			}
		}

		ReleaseMutex(hMutex);
	}

	return(ret);
}
static int close_handle(void* z_handle)
{
	int ret = SSH_ERROR;

	if (z_handle != NULL)
	{
		WaitForSingleObject(hMutex, INFINITE);

		for (int i = 0; i < MAX_HANDLES; i++)
		{
			if (s_handle_table[i].handle == z_handle)
			{
				/* Close handle */
				switch (s_handle_table[i].type)
				{
				case DIR_HANDLE:
				{
					closedir((DIR*)z_handle);
					break;
				}

				case FILE_HANDLE:
				{
					fclose((FILE*)z_handle);
					break;
				}
				}

				/* Remove handle from table */
				s_handle_table[i].handle = NULL;
				s_handle_table[i].session_id = NULL;
				if (s_handle_table[i].path != NULL)
				{
					free(s_handle_table[i].path);
					s_handle_table[i].path = NULL;
				}
				ret = SSH_OK;
				break;
			}
		}

		ReleaseMutex(hMutex);
	}

	return(ret);
}
static int errno_to_ssh_status(int z_errno)
{
	int ret = SSH_FX_OK;

	switch (z_errno)
	{
	case 0:
	{
		ret = SSH_FX_OK;
		break;
	}
	case ENOENT:
	case ENOTDIR:
	case EBADF:
	case ELOOP:
	{
		ret = SSH_FX_NO_SUCH_FILE;
		break;
	}
	case EPERM:
	case EACCES:
	case EFAULT:
	{
		ret = SSH_FX_PERMISSION_DENIED;
		break;
	}
	case ENAMETOOLONG:
	case EINVAL:
	{
		ret = SSH_FX_BAD_MESSAGE;
		break;
	}
	case ENOSYS:
	{
		ret = SSH_FX_OP_UNSUPPORTED;
		break;
	}
	default:
	{
		ret = SSH_FX_FAILURE;
		break;
	}
	}

	return ret;
}

static int check_password(const char* z_user, const char* z_password)
{
	int check = SSH_OK;

	if (_stricmp(z_user, g_user_name.c_str()) != 0)
	{
		check = SSH_ERROR;
	}
	if (_stricmp(z_password, g_password.c_str()) != 0)
	{
		check = SSH_ERROR;
	}
	return check;
}

static int check_publickey(const char* z_user, ssh_key z_public/*, ssh_publickey_state_e z_state*/)
{
	//if (z_state == SSH_PUBLICKEY_STATE_NONE) 
	//{
	//	SSH_LOG(SSH_LOG_NONE, "A");
	//	return SSH_OK;
	//}

	//if (z_state != SSH_PUBLICKEY_STATE_VALID) 
	//{
	//	return SSH_ERROR;
	//}
	//SSH_LOG(SSH_LOG_NONE, "%s %s", z_user, z_password);
	if (_stricmp(z_user, g_user_name.c_str()) != 0)
	{
		return SSH_ERROR;
	}

	//ssh_key key = NULL;
	int result;

	ssh_key privkey;
	ssh_key publickey;
	result = ssh_pki_import_privkey_file(g_rsakey.c_str(),
		NULL,
		NULL,
		NULL,
		&privkey);
	if ((result != SSH_OK) || (privkey == NULL))
	{
		fprintf(stderr,
			"Unable to import public key file %s",
			g_rsakey.c_str());
	}
	else
	{
		result = ssh_pki_export_privkey_to_pubkey(privkey, &publickey);
		if (result == SSH_OK)
		{
			result = ssh_key_cmp(publickey, z_public, SSH_KEY_CMP_PUBLIC);
			ssh_key_free(publickey);
			if (result == 0)
			{
				//SSH_LOG(SSH_LOG_NONE, "B");
				return SSH_OK;
			}
		}
		ssh_key_free(privkey);
	}
	return SSH_ERROR;
}

static int authenticate(ssh_session z_session)
{
	int auth = SSH_ERROR;
	ssh_message message = NULL;

	do
	{
		message = ssh_message_get(z_session);
		if (message == NULL)
		{
			break;
		}
		switch (ssh_message_type(message))
		{
		case SSH_REQUEST_AUTH:
		{
			switch (ssh_message_subtype(message))
			{
			case SSH_AUTH_METHOD_PASSWORD:
			{
				auth = check_password(ssh_message_auth_user(message), ssh_message_auth_password(message));

				if (auth == SSH_OK)
				{
					ssh_message_auth_reply_success(message, 0);
					break;
				}
				else
				{
					ssh_message_reply_default(message);
				}
				break;
			}
			case SSH_AUTH_METHOD_PUBLICKEY:
			{
				auth = check_publickey(ssh_message_auth_user(message), ssh_message_auth_pubkey(message)/*, ssh_message_auth_publickey_state(message)*/);

				if (auth == SSH_OK)
				{
					ssh_message_auth_reply_success(message, 0);
					break;
				}
				else
				{
					ssh_message_reply_default(message);
				}
				break;
			}
			case SSH_AUTH_METHOD_NONE:
			default:
			{
				ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
				ssh_message_reply_default(message);
				break;
			}
			}
			break;
		}
		default:
		{
			ssh_message_reply_default(message);
			break;
		}
		}
		ssh_message_free(message);
	} while (auth == SSH_ERROR);

	return(auth);
}

static ssh_channel open_channel(ssh_session z_session)
{
	ssh_channel chan = NULL;
	ssh_message message = NULL;

	do
	{
		message = ssh_message_get(z_session);

		if (message != NULL)
		{
			switch (ssh_message_type(message))
			{
			case SSH_REQUEST_CHANNEL_OPEN:
			{
				if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
				{
					chan = ssh_message_channel_request_open_reply_accept(message);
					break;
				}
			}
			default:
			{
				ssh_message_reply_default(message);
				break;
			}
			}
			ssh_message_free(message);
		}
	} while ((message != NULL) && (chan == NULL));

	return(chan);
}

static int sftp_subsystem_request(ssh_session z_session)
{
	int ret = SSH_ERROR;
	ssh_message message = NULL;

	do
	{
		message = ssh_message_get(z_session);

		if ((message != NULL) && (ssh_message_type(message) == SSH_REQUEST_CHANNEL))
		{
			int sub_type = ssh_message_subtype(message);

			if (sub_type == SSH_CHANNEL_REQUEST_SUBSYSTEM)
			{
				const char* subsystem = ssh_message_channel_request_subsystem(message);

				if (strcmp(subsystem, "sftp") == 0)
				{
					ret = SSH_OK;
					ssh_message_channel_request_reply_success(message);
				}
			}
		}

		ssh_message_free(message);

	} while (message && (ret == SSH_ERROR));

	return(ret);
}
static void process_sftp_commands(sftp_session z_sftp_sn)
{
	int status = SSH_OK;
	ULONGLONG m_nBytesSend = 0;
	time_t BandwidthStart = 0;
	char log[1024];
	while (g_stop_server == 0)
	{
		if (ssh_channel_poll_timeout(z_sftp_sn->channel, 100000, 0) <= 0)
			break;
		int client_message_type;

		sftp_client_message client_message;

		client_message = sftp_get_client_message(z_sftp_sn);

		if (client_message == NULL)
		{
			break;
		}

		client_message_type = sftp_client_message_get_type(client_message);

		switch (client_message_type)
		{
		case SSH_FXP_OPEN:
		{
			snprintf(log, 1024, "SSH_FXP_OPEN");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_open(client_message);
			break;
		}

		case SSH_FXP_READ:
		{
			snprintf(log, 1024, "SSH_FXP_READ");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_read(client_message, m_nBytesSend, BandwidthStart);
			break;
		}

		case SSH_FXP_WRITE:
		{
			snprintf(log, 1024, "SSH_FXP_WRITE");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_write(client_message);
			break;
		}


		case SSH_FXP_CLOSE:
		{
			snprintf(log, 1024, "SSH_FXP_CLOSE");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_close(client_message);
			break;
		}

		case SSH_FXP_LSTAT:
		{
			snprintf(log, 1024, "SSH_FXP_LSTAT");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_lstat(client_message);
			break;
		}

		case SSH_FXP_FSTAT:
		{
			snprintf(log, 1024, "SSH_FXP_FSTAT");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_fstat(client_message);
			break;
		}

		case SSH_FXP_SETSTAT:
		{
			snprintf(log, 1024, "SSH_FXP_SETSTAT");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_setstat(client_message);
			break;
		}
		case SSH_FXP_FSETSTAT:
		{
			snprintf(log, 1024, "SSH_FXP_FSETSTAT");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_setstat(client_message);
			break;
		}

		case SSH_FXP_OPENDIR:
		{
			snprintf(log, 1024, "SSH_FXP_OPENDIR");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_opendir(client_message);
			break;
		}
		case SSH_FXP_READDIR:
		{
			snprintf(log, 1024, "SSH_FXP_READDIR");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_readdir(client_message);
			break;
		}

		case SSH_FXP_REMOVE:
		{
			snprintf(log, 1024, "SSH_FXP_REMOVE");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_remove(client_message);
			break;
		}

		case SSH_FXP_MKDIR:
		{
			snprintf(log, 1024, "SSH_FXP_MKDIR");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_mkdir(client_message);
			break;
		}

		case SSH_FXP_RMDIR:
		{
			snprintf(log, 1024, "SSH_FXP_RMDIR");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_rmdir(client_message);
			break;
		}

		case SSH_FXP_REALPATH:
		{
			snprintf(log, 1024, "SSH_FXP_REALPATH");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_realpath(client_message);
			break;
		}

		case SSH_FXP_STAT:
		{
			snprintf(log, 1024, "SSH_FXP_STAT");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_stat(client_message);
			break;
		}

		case SSH_FXP_RENAME:
		{
			snprintf(log, 1024, "SSH_FXP_RENAME");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			status = process_rename(client_message);
			break;
		}

		case SSH_FXP_INIT:
		{
			snprintf(log, 1024, "SSH_FXP_INIT");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
		}
		case SSH_FXP_VERSION:
		{
			snprintf(log, 1024, "SSH_FXP_VERSION");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
		}
		case SSH_FXP_READLINK:
		{
			snprintf(log, 1024, "SSH_FXP_READLINK");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
		}
		case SSH_FXP_SYMLINK:
		{
			snprintf(log, 1024, "SSH_FXP_SYMLINK");
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
		}
		default:
		{
			sftp_reply_status(client_message, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
			snprintf(log, 1024, "Message type %d not implemented", client_message_type);
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}
		}

		sftp_client_message_free(client_message);

		if (status == SSH_ERROR)
		{
			break;
		}
	}
}
static void clear_filexfer_attrib(struct sftp_attributes_struct* z_attr)
{
	z_attr->flags = 0;
	z_attr->size = 0;
	z_attr->uid = 0;
	z_attr->gid = 0;
	z_attr->permissions = 0;
	z_attr->atime = 0;
	z_attr->mtime = 0;
}

static void stat_to_filexfer_attrib(const struct stat* z_st, struct sftp_attributes_struct* z_attr)
{
	z_attr->flags = 0;
	z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_SIZE;
	z_attr->size = z_st->st_size;
	z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_UIDGID;
	z_attr->uid = z_st->st_uid;
	z_attr->gid = z_st->st_gid;
	z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS;
	z_attr->permissions = z_st->st_mode;
	z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_ACMODTIME;
	z_attr->atime = (uint32_t)z_st->st_atime;
	z_attr->mtime = (uint32_t)z_st->st_mtime;
}
static int realpath(const char* path, string& long_path)
{
	//MessageBoxA(0, path,0,0);
	int n = (int)strlen(path);
	long_path = path;
	if (long_path[0] == '.')
		long_path[0] = '/';
	if (n > 3)
	{
		int al1 = n - 1;
		int al2 = n - 2;
		int al3 = n - 3;
		if (long_path[al1] == '.' && long_path[al2] == '.' && long_path[al3] == '/')
		{
			int nl = (int)(long_path.size() + 1);
			char* str = new char[nl];
			strcpy_s(str, nl, long_path.c_str());
			for (int i = (int)strlen(str) - 4; i >= 0; i--)
			{
				if (str[i] == '/')
				{
					str[i + 1] = '\0';
					break;
				}
			}
			long_path = str;
			n = (int)long_path.size();
			delete[] str;
		}
	}

	if (n > 1)
	{
		int al = n - 1;
		if (long_path[al] == '.')
			long_path.erase(al, 1);
	}
	if (long_path.empty())
		return NULL;
	else
		return 1;
}
static int process_realpath(sftp_client_message z_client_message)
{
	int ret = SSH_ERROR;
	int status = SSH_FX_FAILURE;
	const char* path = sftp_client_message_get_filename(z_client_message);
	char log[1024];
	if (path != NULL)
	{
		string long_path;

		if (realpath(path, long_path) != NULL)
		{
			//MessageBoxA(0, long_path.c_str(), 0, 0);
			snprintf(log, 1024, "RealPath -> %s", long_path.c_str());
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			sftp_reply_name(z_client_message, long_path.c_str(), NULL);
			ret = SSH_OK;
		}
		else
		{
			status = errno_to_ssh_status(errno);
		}
	}

	if (ret == SSH_ERROR)
	{
		sftp_reply_status(z_client_message, status, NULL);
	}

	return(ret);
}
static int process_opendir(sftp_client_message z_client_message)
{
	int ret = SSH_ERROR;
	DIR* dir = NULL;
	const char* file_name = sftp_client_message_get_filename(z_client_message);
	char log[1024];
	wstring openpath = g_rootpath;
	openpath += stringToWstring(file_name, CP_UTF8);
	//MessageBox(0, openpath.c_str(), 0, 0);

	snprintf(log, 1024, "Open Dir -> %s", file_name);
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (!openpath.empty())
	{
		int len = (int)openpath.size();
		if (len > 1)
		{
			int len1 = len - 1;
			if (openpath[len1] != '/')
				openpath += L"/";
		}
	}
	dir = opendir(openpath.c_str());

	if (dir != NULL)
	{
		string filepath = WstringTostring(openpath, CP_UTF8);
		if (add_handle(DIR_HANDLE, dir, filepath.c_str(), z_client_message->sftp) == SSH_OK)
		{
			ssh_string handle = sftp_handle_alloc(z_client_message->sftp, dir);
			sftp_reply_handle(z_client_message, handle);
			ssh_string_free(handle);
			ret = SSH_OK;
		}
		else
		{
			closedir(dir);
			sftp_reply_status(z_client_message, SSH_FX_FAILURE, "No handle available");
		}
	}
	else
	{
		sftp_reply_status(z_client_message, SSH_FX_NO_SUCH_FILE, "No such directory");
	}
	return(ret);
}
static int process_readdir(sftp_client_message z_client_message)
{
	int ret = SSH_ERROR;
	int entries = 0;
	struct dirent* dentry;
	char log[1024];
	DIR* dir = (DIR*)sftp_handle(z_client_message->sftp, z_client_message->handle);

	if (dir != NULL)
	{
		char long_path[MAX_PATH];
		int path_length;

		ret = SSH_OK;
		strcpy_s(long_path, get_handle_path((void*)dir));

		snprintf(log, 1024, "Read Dir -> %s", long_path);
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

		path_length = (int)strlen(long_path);

		for (int i = 0; i < NUM_ENTRIES_PER_PACKET; i++)
		{
			dentry = readdir(dir);

			if (dentry != NULL)
			{
				struct sftp_attributes_struct attr;
				struct stat st;
				char long_name[_MAX_FNAME];

				strcpy_s(&long_path[path_length], _MAX_FNAME, dentry->d_name);

				wstring wlong_path = stringToWstring(long_path, CP_UTF8);

				string clong_path = WstringTostring(wlong_path, CP_ACP);
				if (stat(clong_path.c_str(), &st) == 0)
				{
					stat_to_filexfer_attrib(&st, &attr);
				}
				else
				{
					clear_filexfer_attrib(&attr);
				}

				sftp_reply_names_add(z_client_message, dentry->d_name, readdir_long_name(dentry->d_name, &st, long_name), &attr);
				entries++;
			}
			else
			{
				break;
			}
		}

		if (entries > 0)
		{
			ret = sftp_reply_names(z_client_message);
		}
		else
		{
			sftp_reply_status(z_client_message, SSH_FX_EOF, NULL);
		}
	}
	else
	{
		sftp_reply_status(z_client_message, SSH_FX_INVALID_HANDLE, NULL);
	}

	return(ret);
}
static int process_close(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	void* handle = (DIR*)sftp_handle(z_client_message->sftp, z_client_message->handle);

	ret = close_handle(handle);

	char log[1024];
	snprintf(log, 1024, "Close handle");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (ret == SSH_OK)
	{
		sftp_reply_status(z_client_message, SSH_FX_OK, NULL);
	}
	else
	{
		sftp_reply_status(z_client_message, SSH_FX_BAD_MESSAGE, "Invalid handle");
	}

	return(ret);
}
static int process_stat(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	const char* file_name = sftp_client_message_get_filename(z_client_message);
	struct sftp_attributes_struct attr;
	struct stat st;
	wstring wfile_name = g_rootpath;
	wfile_name += stringToWstring(file_name, CP_UTF8);
	string cfile_name = WstringTostring(wfile_name, CP_ACP);

	char log[1024];
	snprintf(log, 1024, "STAT %s", cfile_name.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (stat(cfile_name.c_str(), &st) == 0)
	{
		stat_to_filexfer_attrib(&st, &attr);
		sftp_reply_attr(z_client_message, &attr);
	}
	else
	{
		int status = errno_to_ssh_status(errno);
		sftp_reply_status(z_client_message, status, NULL);
		ret = SSH_ERROR;
	}

	return(ret);
}
static int process_open(sftp_client_message z_client_message)
{
	int ret = SSH_ERROR;
	const char* file_name = sftp_client_message_get_filename(z_client_message);
	wstring wfile_name = stringToWstring(file_name, CP_UTF8);

	uint32_t message_flags = z_client_message->flags;
	FILE* fp = NULL;
	wchar_t mode[4];

	if (((message_flags & (uint32_t)SSH_FXF_READ) == SSH_FXF_READ) &&
		((message_flags & (uint32_t)SSH_FXF_WRITE) == SSH_FXF_WRITE))
	{
		if ((message_flags & (uint32_t)SSH_FXF_CREAT) == SSH_FXF_CREAT)
		{
			wcscpy_s(mode, L"wb+");
		}
		else
		{
			wcscpy_s(mode, L"rb+");
		}
	}
	else if ((message_flags & (uint32_t)SSH_FXF_READ) == SSH_FXF_READ)
	{
		if ((message_flags & (uint32_t)SSH_FXF_APPEND) == SSH_FXF_APPEND)
		{
			wcscpy_s(mode, L"ab+");
		}
		else
		{
			wcscpy_s(mode, L"rb");
		}
	}
	else if ((message_flags & (uint32_t)SSH_FXF_WRITE) == SSH_FXF_WRITE)
	{
		wcscpy_s(mode, L"wb");
	}

	wstring m_pathname = g_rootpath;
	m_pathname += wfile_name;
	_wfopen_s(&fp, m_pathname.c_str(), mode);

	char log[1024];
	snprintf(log, 1024, "Open %ws", m_pathname.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (fp != NULL)
	{
		if (add_handle(FILE_HANDLE, fp, file_name, z_client_message->sftp) == SSH_OK)
		{
			ssh_string handle = sftp_handle_alloc(z_client_message->sftp, fp);
			sftp_reply_handle(z_client_message, handle);
			ssh_string_free(handle);
			ret = SSH_OK;
		}
		else
		{
			fclose(fp);
			sftp_reply_status(z_client_message, SSH_FX_FAILURE, "No handle available");
		}
	}
	else
	{
		sftp_reply_status(z_client_message, SSH_FX_NO_SUCH_FILE, "No such file");
	}

	return(ret);
}
static int process_read(sftp_client_message z_client_message, ULONGLONG& pSend, time_t& pStart)
{
	int ret = SSH_ERROR;
	FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);

	char log[1024];
	snprintf(log, 1024, "Reading File");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (fp != NULL)
	{
		if (m_Bandwidth > 0 && pSend <= 0)
		{
			pSend = m_Bandwidth;
		}
		if (pStart <= 0)
			pStart = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
		if (_fseeki64(fp, z_client_message->offset, SEEK_SET) == 0)
		{
			uint32_t n;
			char* buffer = (char*)malloc((z_client_message->len) * sizeof(char));

			ret = SSH_OK;

			n = (uint32_t)fread(buffer, sizeof(char), z_client_message->len, fp);

			if (n > 0)
			{
				sftp_reply_data(z_client_message, buffer, n);
				if (pSend < n)
					pSend = 0;
				else
					pSend -= n;
				if (m_Bandwidth > 0 && pSend <= 0)
				{
					time_t BandwidthEnd = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
					time_t BandwidthValue = BandwidthEnd - pStart;

					if (BandwidthValue > 1000)
					{
						pSend = m_Bandwidth;
					}
					else
					{

						time_t BandwidthValue1 = 1000 - BandwidthValue;
						Sleep(BandwidthValue1);
						pSend = m_Bandwidth;
					}
					pStart = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
				}
			}
			else
			{
				sftp_reply_status(z_client_message, SSH_FX_EOF, "EOF encountered");
			}

			free(buffer);
		}
		else
		{
			sftp_reply_status(z_client_message, SSH_FX_FAILURE, NULL);
		}
	}
	else
	{
		sftp_reply_status(z_client_message, SSH_FX_INVALID_HANDLE, NULL);
	}

	return(ret);
}
static int process_write(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);

	if (fp != NULL)
	{
		size_t n;
		size_t len = ssh_string_len(z_client_message->data);

		char log[1024];
		snprintf(log, 1024, "Writing File (%I64u %I64u)", len, z_client_message->offset);
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);

		_fseeki64(fp, z_client_message->offset, SEEK_SET);
		n = fwrite(sftp_client_message_get_data(z_client_message), sizeof(char), len, fp);

		if (n > 0)
		{
			sftp_reply_status(z_client_message, SSH_FX_OK, NULL);
		}
		else
		{
			sftp_reply_status(z_client_message, SSH_FX_FAILURE, "Write error");
		}
	}
	else
	{
		sftp_reply_status(z_client_message, SSH_FX_INVALID_HANDLE, NULL);
		ret = SSH_ERROR;
	}

	return(ret);
}
static int process_fstat(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);
	int fd = _fileno(fp);
	struct sftp_attributes_struct attr;
	struct stat st;

	if (fstat(fd, &st) == 0)
	{
		stat_to_filexfer_attrib(&st, &attr);
		sftp_reply_attr(z_client_message, &attr);
	}
	else
	{
		int status = errno_to_ssh_status(errno);
		sftp_reply_status(z_client_message, status, NULL);
		ret = SSH_ERROR;
	}

	return(ret);
}
static int process_lstat(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	const char* file_name = sftp_client_message_get_filename(z_client_message);
	struct sftp_attributes_struct attr;
	struct stat st;
	wstring m_pathname = g_rootpath;
	m_pathname += stringToWstring(file_name, CP_UTF8);
	string cpathname = WstringTostring(m_pathname, CP_ACP);

	char log[1024];
	snprintf(log, 1024, "LStat %s", cpathname.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (stat(cpathname.c_str(), &st) == 0)
	{
		stat_to_filexfer_attrib(&st, &attr);
		sftp_reply_attr(z_client_message, &attr);
	}
	else
	{
		sftp_reply_status(z_client_message, 0, NULL);
	}

	return(ret);
}
static int process_setstat(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	int status = SSH_FX_OK;
	const char* file_name = NULL;

	if (sftp_client_message_get_type(z_client_message) == SSH_FXP_FSETSTAT)
	{
		FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);
		file_name = get_handle_path(fp);
	}
	else
	{
		file_name = sftp_client_message_get_filename(z_client_message);
	}

	char log[1024];
	snprintf(log, 1024, "SetStat %s", file_name);
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_SIZE)
	{
		FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);
		if (_chsize_s(_fileno(fp), z_client_message->attr->size) == -1)
		{
			//ret = SSH_ERROR;
			//status = errno_to_ssh_status(errno);
		}
	}
	wstring m_pathname = g_rootpath;
	m_pathname += stringToWstring(file_name, CP_UTF8);
	if (z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS)
	{
		if (_wchmod(m_pathname.c_str(), z_client_message->attr->permissions & (uint32_t)07777) == -1)
		{
			//ret = SSH_ERROR;
			//status = errno_to_ssh_status(errno);
		}
	}

	if (z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_ACMODTIME)
	{
		HANDLE hFile = CreateFile(m_pathname.c_str(),
			GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			SYSTEMTIME actime = TimetToSystemTimeEx(z_client_message->attr->atime);
			SYSTEMTIME modtime = TimetToSystemTimeEx(z_client_message->attr->mtime);
			FILETIME aft, mft;
			SystemTimeToFileTime(&actime, &aft);
			SystemTimeToFileTime(&modtime, &mft);
			SetFileTime(hFile, NULL, &aft, &mft);
			CloseHandle(hFile);
		}
	}

	if (z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_UIDGID)
	{

	}

	sftp_reply_status(z_client_message, status, NULL);

	return(ret);
}
static int process_remove(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	int status = SSH_FX_OK;
	const char* file_name = sftp_client_message_get_filename(z_client_message);
	wstring m_pathname = g_rootpath;
	m_pathname += stringToWstring(file_name, CP_UTF8);
	//DeleteFile(m_pathname.c_str());

	char log[1024];
	snprintf(log, 1024, "Remove %ws", m_pathname.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (_wunlink(m_pathname.c_str()) < 0)
	{
		status = errno_to_ssh_status(errno);
	}
	sftp_reply_status(z_client_message, status, NULL);

	return(ret);
}
static int process_rename(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	int status = SSH_FX_FAILURE;
	const char* old_file_name = sftp_client_message_get_filename(z_client_message);
	const char* new_file_name = sftp_client_message_get_data(z_client_message);
	wstring m_oldpathname = g_rootpath;
	m_oldpathname += stringToWstring(old_file_name, CP_UTF8);
	wstring m_newpathname = g_rootpath;
	m_newpathname += stringToWstring(new_file_name, CP_UTF8);
	//struct stat st;

	/* Check old file name exists */
	//if (lstat(old_file_name, &st) == 0)
	//{
	//	/* Check new file name does not already exist */
	//	if (stat(new_file_name, &st) == -1)
	//	{
	if (_wrename(m_oldpathname.c_str(), m_newpathname.c_str()) == 0)
	{
		//ret = SSH_OK;
		status = SSH_FX_OK;
	}
	//		else
	//		{
	//			status = errno_to_ssh_status(errno);
	//		}
	//	}
	//}
	//else
	//{
	//	status = errno_to_ssh_status(errno);
	//}

	sftp_reply_status(z_client_message, status, NULL);

	char log[1024];
	snprintf(log, 1024, "ReName %ws", m_newpathname.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	return(ret);
}
static int process_mkdir(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	int status = SSH_FX_OK;
	const char* dir_name = sftp_client_message_get_filename(z_client_message);

	wstring m_dirpathname = g_rootpath;
	m_dirpathname += stringToWstring(dir_name, CP_UTF8);


	char log[1024];
	snprintf(log, 1024, "Make Dir -> %ws", m_dirpathname.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (_wmkdir(m_dirpathname.c_str()) < 0)
	{
		//MessageBox(0, m_dirpathname.c_str(),0,0);
		status = errno_to_ssh_status(errno);
		//ret = SSH_ERROR;
	}

	sftp_reply_status(z_client_message, status, NULL);

	return(ret);
}
static int process_rmdir(sftp_client_message z_client_message)
{
	int ret = SSH_OK;
	int status = SSH_FX_OK;
	const char* dir_name = sftp_client_message_get_filename(z_client_message);
	wstring m_dirpathname = g_rootpath;
	m_dirpathname += stringToWstring(dir_name, CP_UTF8);

	char log[1024];
	snprintf(log, 1024, "Remove Dir -> %ws", m_dirpathname.c_str());
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	if (_wrmdir(m_dirpathname.c_str()) < 0)
	{
		//ret = SSH_ERROR;
		status = errno_to_ssh_status(errno);
	}

	sftp_reply_status(z_client_message, status, NULL);

	return(ret);
}
static DWORD WINAPI Thread_sftp_server(LPVOID lpParam)
{
	ssh_session session = (ssh_session)lpParam;
	ssh_channel chan = NULL;
	sftp_session sftp_sn = NULL;
	int auth = SSH_ERROR;
	int sftp = SSH_ERROR;
	char log[1024];

	snprintf(log, 1024, "Thread_sftp_server is started");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	do
	{
		//SSH_LOG(SSH_LOG_NONE, "ssh_handle_key_exchange() ");
		if (ssh_handle_key_exchange(session) != SSH_OK)
		{
			snprintf(log, 1024, "Error ssh_handle_key_exchange: %s", ssh_get_error(session));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}

		//SSH_LOG(SSH_LOG_NONE, "authenticate() ");
		auth = authenticate(session);

		if (auth == SSH_ERROR)
		{
			snprintf(log, 1024, "Error authenticate: %s", ssh_get_error(session));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}
		//SSH_LOG(SSH_LOG_NONE, "open_channel() ");
		chan = open_channel(session);

		if (chan == NULL)
		{
			snprintf(log, 1024, "Error open_channel: %s", ssh_get_error(session));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}

		//SSH_LOG(SSH_LOG_NONE, "sftp_subsystem_request() ");
		sftp = sftp_subsystem_request(session);

		if (sftp == SSH_ERROR)
		{
			snprintf(log, 1024, "Error sftp_subsystem_request: %s", ssh_get_error(session));
			SSH_LOG(SSH_LOG_NONE, log);
			appendToLogFile(log, __func__);
			break;
		}

		//SSH_LOG(SSH_LOG_NONE, "sftp_server_new() ");
		sftp_sn = sftp_server_new(session, chan);

		if (sftp_sn == NULL)
		{
			break;
		}

		//SSH_LOG(SSH_LOG_NONE, "sftp_server_init() ");
		if (sftp_server_init(sftp_sn) < 0)
		{
			break;
		}

		snprintf(log, 1024, "Process command for [%s] connection", session->peer_address);
		SSH_LOG(SSH_LOG_NONE, log);
		appendToLogFile(log, __func__);
		process_sftp_commands(sftp_sn);


	} while (g_stop_server == 0);

	if (sftp_sn != NULL)
	{
		sftp_free(sftp_sn);
	}

	ssh_disconnect(session);
	ssh_free(session);


	snprintf(log, 1024, "Thread_sftp_server is finished");
	SSH_LOG(SSH_LOG_NONE, log);
	appendToLogFile(log, __func__);

	return 0;
}