The current project is created using Visual Studio 2008
on Windows XP. It has LDNS[1] compiled from source, and
WinPcap[3.1] precompiled.

#Steps to compile
1. Download WinPcap from [3]
	1.1 Install it
	1.2 If you wan to recompile, dowload the devel package [3.1]
		1.2.1 unzip it to winpcap
		1.2.2 Add header and lib folders to project additional dirs	

CHANGES:
0. Used getopt for Windows from [2]
1. Used inet_ntop from ldns implementation,
	since its supported on Windows >= Server 2003
2. The default log directory is %APP_DATA%\passivedns
3. Original Linux program used signals SIGUSR1 to print capture statistics
	and SIGALRM to clean timedout sessions.
	Windows does not support signals, and both functions are implemented
	in separate threads.
		The first thread prints capture statistics on each 10s. Its disabled in daemon mode.
		The second thread sets flags for cleaning sessions and dns records. The cleaning is
		done in master(capture thread).
4. If you use the -u USER option, the user starting the daemon must have "Replace a process token level".
	To enable this do:
	4.1 Run Secpol.msc. Open the 'Local policies' folder.
	4.2 Go to 'User Rights Assignment' and find 'Replace a process token level'
	4.3 Add the user starting the daemon to this right
	4.5 On my setup, I also had to add the daemon user to the Administrators group.
	
5. If you use the daemon(-D), user(-u) option, passivedns will run in the background.
	To stop it you can:
	1) Delete the pid file.
		Process will stop after TIMEOUT(default 60s)
	2) Send SIGINT to the daemon process.
	3) Kill it from the Taks manger.
	
6. Not implemented
	3.1 chroot() - not avaialble in Windows
	

ISSUES:
8) static linked pdns requires WinPcap installed (wpcap.dll)!
!) No issues on Windows Server 2003
?) Fails to get packets on Windows 2008
	- Some Winpcap issue or OS security configurations ?
	- fails to start using -D -u USER
?) Win2012
	- fails to start using -D -u USER

REFERENCES:
[1] http://wp.eddiesheffield.com/?p=18
[2] http://note.sonots.com/Comp/CompLang/cpp/getopt.html
[2.1] http://www.nlnetlabs.nl/projects/ldns/
[3] http://www.winpcap.org/install/default.htm
[3.1] http://www.winpcap.org/devel.htm

PROGRAMMING NOTES:
3) use socket_storage for IPv4/6 adresses ?
	http://www.kame.net/newsletter/19980604/