import cx_Freeze
import sys

base = None
if sys.platform == 'win32':
    base = "Win32GUI"

executables = [cx_Freeze.Executable("GUI.py", base=base, icon='img/bitproof.ico')]

cx_Freeze.setup(
    name = "BitProof",
    options = {"build_exe": {"packages":["Tkinter","tkFont", "tkMessageBox", "PIL.Image", "PIL.ImageTk", "os", "pcap",
                                         "dpkt", "geolite2", "tld", "socket", "urllib"], "include_files":["analyze.png",
                                         "bitproof.ico", "bitproof.png", "clean.png", "crawl.png", "more.png",
                                         "sniff.png", "start.png", "stop.png", "analisys.py", "ntbit2Info.py",
                                         "ntclean.py", "ntdefrag.py", "ntdomain_name.py", "ntethernet.py",
                                         "ntgeneral.py", "ntip_address.py", "ntMainCrawler.py", "ntMainSniffer.py",
                                         "ntnmap.py", "ntrobots_txt.py", "ntsaveSession.py", "ntwhois.py", "winSock.py"]}},
    version = "1.5.0",
    description = "BitProof",
    executables = executables
)