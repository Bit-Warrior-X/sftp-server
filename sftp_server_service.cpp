#include "sftp_server_service.h"
#include "MainSFTPServer.h"
#include "ThreadPool.h"

#include <WtsApi32.h>

#pragma comment(lib, "Wtsapi32.lib")

void SftpServerService::OnStart(DWORD /*argc*/, TCHAR** /*argv[]*/) {

  sftp_server_start();
  // Queue the main service function for execution in a worker thread.
  //CThreadPool::QueueUserWorkItem(&SftpServerService::ServiceWorkerThread, this);
}

void SftpServerService::ServiceWorkerThread(void)
{
    sftp_server_start();
    SetEvent(m_hStoppedEvent);
    
}
void SftpServerService::OnStop() {
    sftp_server_stop();
    //if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    //{
    //    throw GetLastError();
    //}
    //sftp_server_release();
}

void SftpServerService::OnSessionChange(DWORD evtType,
                                         WTSSESSION_NOTIFICATION* notification) {
  // Let's get user name and the action they did.
  TCHAR* buf = nullptr;
  DWORD size = 0;

  BOOL res = ::WTSQuerySessionInformation(nullptr, notification->dwSessionId,
                                          WTSUserName, &buf, &size);

  CString message;

  if (!res) {
    message = _T("Can't get user name ");
  } else {
    SYSTEMTIME sysTime = {0};
    ::GetSystemTime(&sysTime);

    message.Format(_T("%2d.%2d.%4d|%2d:%2d:%2d|User name: %s "),
                   sysTime.wDay, sysTime.wMonth, sysTime.wYear,
                   sysTime.wHour, sysTime.wMinute, sysTime.wSecond, buf);
  }

  ::WTSFreeMemory(buf);

  // Get the event type.
  switch (evtType) {
    case WTS_CONSOLE_CONNECT:
      message.Append(_T("connected."));
    break;

    case WTS_CONSOLE_DISCONNECT:
      message.Append(_T("disconnected."));
    break;

    case WTS_REMOTE_CONNECT:
      message.Append(_T("connected remotely."));
    break;

    case WTS_REMOTE_DISCONNECT:
      message.Append(_T("disconnected remotely."));
    break;

    case WTS_SESSION_LOGON:
      message.Append(_T("logged on."));
    break;

    case WTS_SESSION_LOGOFF:
      message.Append(_T("logged off."));
    break;
   
    case WTS_SESSION_LOCK:
      message.Append(_T("locked the PC."));
    break;

    case WTS_SESSION_UNLOCK:
      message.Append(_T("unlocked the PC."));
    break;

    // Didn't add WTS_SESSION_REMOTE_CONTROL handler.

    default:
      message.Append(_T("performed untracked operation."));
    break;
  }
}
