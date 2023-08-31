#pragma once
#ifndef MAINSFTPSERVER_H
#define MAINSFTPSERVER_H

int sftp_server_start();
int sftp_server_stop();
int sftp_server_release();
int sftp_set_log_path(wchar_t * str);
void appendToLogFile(const char* logMessage, const char* functionName);

#endif

