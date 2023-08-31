#ifndef SERVER_SFTP_SERVICE_H
#define SERVER_SFTP_SERVICE_H

#include <fstream>

#include "service_base.h"

class SftpServerService : public ServiceBase {
 public:
  SftpServerService(const SftpServerService& other) = delete;
  SftpServerService& operator=(const SftpServerService& other) = delete;

  SftpServerService(SftpServerService&& other) = delete;
  SftpServerService& operator=(SftpServerService&& other) = delete;

  virtual ~SftpServerService(void) {
      if (m_hStoppedEvent)
      {
          CloseHandle(m_hStoppedEvent);
          m_hStoppedEvent = NULL;
      }
  }
  SftpServerService()
   : ServiceBase(_T("PathSolutions SFTP Service"),
                 _T("PathSolutions SFTP Service"),
                 SERVICE_DEMAND_START,
                 SERVICE_ERROR_NORMAL,
                 SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE) {
      m_fStopping = FALSE;

      // Create a manual-reset event that is not signaled at first to indicate 
      // the stopped signal of the service.
      m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
      if (m_hStoppedEvent == NULL)
      {
          throw GetLastError();
      }
  }

protected:
    void ServiceWorkerThread(void);
 private:
   void OnStart(DWORD argc, TCHAR* argv[]) override;
   void OnStop() override;
   void OnSessionChange(DWORD evtType,
                        WTSSESSION_NOTIFICATION* notification) override;

private:
    BOOL m_fStopping;
    HANDLE m_hStoppedEvent;
};

#endif // SERVER_SFTP_SERVICE_H
