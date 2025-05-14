# sftp-server

SFTP server working as a Windows service.

## Features

* Secure File Transfer Protocol (SFTP) support via **libssh**
* Runs as a Windows Service (`SERVICE_DEMAND_START`)
* Configurable root directory and single-user authentication
* Customizable logging with registry-backed settings

## Prerequisites

* **Windows** 7/8/10/Server
* **Visual Studio** 2015 or later (C++ development workload)
* **libssh** (headers and libraries)
* **Windows SDK** (for service APIs)
* **Wtsapi32.lib** (session-change notifications)
* **Dirent** for Windows (included in `include/`)

## Building from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/Bit-Warrior-X/sftp-server.git
   cd sftp-server
   ```
2. Open **windows\_service.sln** in Visual Studio.
3. In Project Properties:

   * **C/C++ → Additional Include Directories**: add `$(SolutionDir)include` and your **libssh** include path.
   * **Linker → Additional Library Directories**: add your **libssh** lib path.
   * **Linker → Input → Additional Dependencies**: add `libssh.lib;Ws2_32.lib;Wtsapi32.lib;Crypt32.lib;Advapi32.lib`.
4. Build in **Release** (or **Debug**) configuration.

## Configuration

Place the following files in the service user’s profile directory (default `%USERPROFILE%`):

* `Config.ini`
* `ssh_host_rsa_key`
* `ssh_host_rsa_key.pub`

Example **Config.ini**:

```ini
# Root path for SFTP shares
RootPath=C:\SFTP\Root

# SFTP login credentials
User=admin
Password=admin
```

> **Note:**
>
> * If the service runs under **LocalSystem**, `%USERPROFILE%` typically resolves to `C:\Windows\system32\config\systemprofile`.

## Generating SSH Host Keys

Use **ssh-keygen** (from Git for Windows or OpenSSH) to generate keys:

```powershell
ssh-keygen -t rsa -b 2048 -m PEM -f ssh_host_rsa_key -N ""
```

Copy both `ssh_host_rsa_key` and `ssh_host_rsa_key.pub` alongside **Config.ini**.

## Usage

### Install the Service

```powershell
SFTPService.exe -i
```

* Installs the **PathSolutions SFTP Service**
* Copies `Config.ini` and host keys into `%USERPROFILE%`

Start it via Services console or:

```powershell
sc start "PathSolutions SFTP Service"
```

### Uninstall the Service

```powershell
SFTPService.exe -u
```

### Configure Logging

* Default log file: `sftp-log.txt` in the service working directory
* To customize:

  ```powershell
  SFTPService.exe -l C:\Logs\sftp.log
  ```

  This writes the path to the registry under `HKCU\SOFTWARE\PathSolutionSFTPServer\LogPath`.

### Run in Console (Debug)

```powershell
SFTPService.exe -l C:\Logs\console.log
```

* Runs the service logic in the console.
* Press **Ctrl+C** to stop.

## Directory Structure

```
include/                  # Third-party headers (e.g., dirent)
lib/                      # libssh libraries and headers
main.cpp                  # Service entry point & CLI
GlobalFunction.*          # String/time conversion utilities
MainSFTPServer.*          # Core SFTP server logic (libssh)
service_base.*            # Windows service framework
service_installer.*       # Installation/uninstallation logic
sftp_server_service.*     # Service start/stop handlers
user_tracker_service.*    # (Optional) Session-tracking service
ThreadPool.h              # Windows thread-pool helper
windows_service.sln       # Visual Studio solution
```

## License

This project is released under the [Unlicense](LICENSE).

## Contributing

Contributions welcome—please open issues or pull requests!
