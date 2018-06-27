# BitProof
Simply Web Crawler, IP Sniffer and Windows cleaning tools for Windows

ASAP will be release a patch for Lunix OS GUI & Lunix Clean

Requirement:

	- Python 2.7.x
	- Nmap --> https://nmap.org/
	- Whois? --> https://docs.microsoft.com/en-us/sysinternals/downloads/whois
	- Npcap --> https://nmap.org/npcap/ (Check the 'API WinPcap')
	- pypcap lib --> https://github.com/pynetwork/pypcap (follow the setup instruction)

When you have all install, you need to make the library visible to the OS:
		
	- Go to 'This PC'
	- Right clink on it and 'Proprieties'
	- Click on 'Advanced System Settings'
	- Go to 'Environment Variables'
	- Find 'PATH' or create it if dosen't exist 
	- If you already have 'PATH' and a new entry; double clik on 'PATH' and 'Modify'
	- Find the path where you install all the libraries and add to 'PATH'
	- Save changes and now you are ready for run the software

For run the software:
	
	- Open the command prompt or Windows PowerShell with Administrator privileges
	- Go to the directory where is save BitProof
	- Type in the console "python GUI.py" and it will open the software

	OR

	- Go to the BitProof direcotry folder
	- Hold 'Shift' and Right Clik on the open folder
	- Click 'Open Windows PowerShell here' or 'Open command prompt here'
	- Type in the console "python GUI.py" and it will open the software

It will expect in the version 1.6.0 the setup for all packages will complete and the .exe will be complete

Thank You for use BitProof
