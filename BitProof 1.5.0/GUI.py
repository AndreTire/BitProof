from Tkinter import *               # frame components

from winSock import *               # for pcap socket and winsock
from analisys import *              # for the sniffing in the backbone LAN
from ntmainCrawler import *         # for the cralwer function about web sites domain
from ntclean import *               # for the win Clean disk C:\Windows\System32
from ntdefrag import *              # for the win Defrag disk C:\Windows\System32

import Tkinter as tk                # tk frame
import tkFont as tkfont             # tk font standard
import tkMessageBox as tkbox        # tk messagebox
import PIL.Image                    # img lib
import PIL.ImageTk                  # img for Tk frame
import os                           # os lib
import sys                          # sys lib
import time                         # time lib
import datetime                     # datetime lib


# Tabulation variables
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


# Create the dir for the caputre file save
ROOT_DIR = 'capture'
create_dir(ROOT_DIR)


# init the winSock at the star of the mainloop() thread to be the software more resposive at I/O user
pc, decode = initWinSock()


# Catch the os timestamp for the name file about capture session
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + '\n'  # file name
stFormatted = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H-%M-%S')  # directory name
project_dir = ROOT_DIR + '/' + stFormatted
create_dir(project_dir)

version = "1.5.0"
mode = "demo"

# Main software, it manage all the frame for the different function
class SampleApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.iconbitmap('img/bitproof.ico')

        self.geometry('800x600')
        self.minsize(800, 600)
        self.maxsize(800, 600)

        if mode == "demo":
            self.title("BitProof demo v" + version)
        else:
            self.title("BitProof")

        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold", slant="italic")

        # the container is where we'll stack a bunch of frames
        # on top of each other, then the one we want visible
        # will be raised above the others
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (frameCrawler, frameSniffer, frameClean):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame

            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("frameCrawler")

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()


# Crawler
class frameCrawler(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        # Logo
        img = PIL.Image.open("img/bitproof.png")
        logo = PIL.ImageTk.PhotoImage(img)
        lblLogo = tk.Label(self, image=logo, bg='#404040')
        lblLogo.img = logo
        lblLogo.grid(rowspan=2, column=0)

        # Title
        lblTitle = tk.Label(self, text="BitProof v" + version, font=('Helvetica', 25), bg='#404040', fg='#146C27', width=30,
                         height=2, anchor='w', padx=50, pady=2)
        lblTitle.grid(row=0, column=1, columnspan=10, sticky='we')

        # Running OS
        if os.name == "nt":
            opsys = "Windows 10"
        else:
            opsys = "Linux"

        if sys.maxsize > 2 ** 32:
            bit = " x64 bit"
        else:
            bit = " x32 bit"
        osys = opsys + bit + " GNU GPL Licences 2018"

        lblOS = tk.Label(self, text=osys, font=('Helvetica', 12), bg='#404040', fg='#146C27', width=30, height=2,
                      anchor='w', padx=50)
        lblOS.grid(row=1, column=1, columnspan=10, sticky='we')

        # Crawler
        imgC = PIL.Image.open("img/crawl.png")
        logoC = PIL.ImageTk.PhotoImage(imgC)
        btnCrawler = tk.Button(self, image=logoC, bg='#1E90FF', width=15, height=100, padx=4, relief=GROOVE,
                               command=lambda: controller.show_frame("frameCrawler"))
        btnCrawler.img = logoC
        # btnCrawler = tk.Button(self, text="Cralwer", font=('Helvetica', 12), bg='#1E90FF', fg='#FFFFFF', width=12, height=5, relief=GROOVE, command=lambda: controller.show_frame("frameCrawler"))
        btnCrawler.grid(row=2, column=0, rowspan=4, sticky='we')

        # Sniffer
        imgS = PIL.Image.open("img/sniff.png")
        logoS = PIL.ImageTk.PhotoImage(imgS)
        btnSniffer = tk.Button(self, image=logoS, bg='#404040', width=15, height=100, padx=4, relief=GROOVE,
                               command=lambda: controller.show_frame("frameSniffer"))
        btnSniffer.img = logoS
        # btnSniffer = tk.Button(self, text="Sniffer", font=('Helvetica', 12), bg='#404040', fg='#146C27', width=12, height=5, padx=4, relief=GROOVE, command=lambda: controller.show_frame("frameSniffer"))
        btnSniffer.grid(row=6, column=0, rowspan=4, sticky='we')

        # nt clean up
        if os.name == "nt":
            imgC = PIL.Image.open("img/clean.png")
            logoC = PIL.ImageTk.PhotoImage(imgC)
            btnClean = tk.Button(self,  image=logoC, bg='#404040', width=12, height=100, padx=4, relief=GROOVE,
                                 command=lambda: controller.show_frame("frameClean"))
            btnClean.img = logoC
            btnClean.grid(row=10, column=0, rowspan=4, sticky='we')

        lblSpace = tk.Label(self, bg='#404040', fg='#146C27', height=12)
        lblSpace.grid(row=14, column=0, rowspan=6, sticky='we')


        # code..
        lblName = tk.Label(self, text="Nome website", font=('Helvetica', 10), anchor='w')
        lblName.grid(row=3, column=2, sticky='we')

        lblURL = tk.Label(self, text="URL da analizzare", font=('Helvetica', 10), anchor='w')
        lblURL.grid(row=3, column=4, sticky='we')

        name = StringVar()
        url = StringVar()

        txtName = tk.Entry(self, textvariable=name)
        txtName.grid(row=4, column=2, sticky='we')

        txtURL = tk.Entry(self, textvariable=url)
        txtURL.grid(row=4, column=4, sticky='we')

        imgA = PIL.Image.open("img/analyze.png")
        logoA = PIL.ImageTk.PhotoImage(imgA)
        btnSend = tk.Button(self, image=logoA, relief=GROOVE,
                            command=lambda: crawler(self, name.get(), url.get()))
        btnSend.img = logoA
        btnSend.grid(row=4, column=6, sticky='we')

        # Method get crawling function
        def crawler(self, name, url):
            if name != ""  and url != "":
                try:
                    name, url, domain_name, ip_address, nmap, robots_txt, whois = gather_info(name, url)

                    imgGoDir = PIL.Image.open("img/more.png")
                    logoGoDir = PIL.ImageTk.PhotoImage(imgGoDir)
                    btnGoDir = tk.Button(self, image=logoGoDir, relief=GROOVE,
                                         command=lambda: os.startfile(os.path.abspath("") + "\websites\\" + name))
                    btnGoDir.img = logoGoDir
                    btnGoDir.grid(row=16, column=2, sticky='we')

                    lblName_Crawlertxt = tk.Label(self, text="Nome:", font=('Helvetica', 10), anchor='w')
                    lblName_Crawlertxt.grid(row=6, column=2, sticky='we')
                    lblName_Crawler = tk.Label(self, text=name, font=('Helvetica', 10), anchor='w')
                    lblName_Crawler.grid(row=6, column=4, sticky='we')

                    lblURL_Crawlertxt = tk.Label(self, text="URL:", font=('Helvetica', 10), anchor='w')
                    lblURL_Crawlertxt.grid(row=7, column=2, sticky='we')
                    lblURL_Crawler = tk.Label(self, text=url, font=('Helvetica', 10), anchor='w')
                    lblURL_Crawler.grid(row=7, column=4, sticky='we')

                    lblDomaintxt = tk.Label(self, text="Dominio:", font=('Helvetica', 10), anchor='w')
                    lblDomaintxt.grid(row=8, column=2, sticky='we')
                    lblDomain = tk.Label(self, text=domain_name, font=('Helvetica', 10), anchor='w')
                    lblDomain.grid(row=8, column=4, sticky='we')

                    lblNmaptxt = tk.Label(self, text="NMAP:", font=('Helvetica', 10), anchor='w')
                    lblNmaptxt.grid(row=9, column=2, sticky='we')

                    nmapl = nmap.split('\n')
                    lbl1 = tk.Label(self, text='(' + nmapl[1], font=('Helvetica', 10), anchor='w')
                    lbl1.grid(row=9, column=4, columnspan=6, sticky='we')

                    lbl2 = tk.Label(self, text=nmapl[2], font=('Helvetica', 10), anchor='w')
                    lbl2.grid(row=10, column=4, sticky='we')

                    lbl3 = tk.Label(self, text=nmapl[3], font=('Helvetica', 10), anchor='w')
                    lbl3.grid(row=11, column=4, sticky='we')

                    lbl4 = tk.Label(self, text=nmapl[4], font=('Helvetica', 10), anchor='w')
                    lbl4.grid(row=12, column=4, sticky='we')

                    lbl5 = tk.Label(self, text=nmapl[5], font=('Helvetica', 10), anchor='w')
                    lbl5.grid(row=13, column=4, sticky='we')

                    lbl6 = tk.Label(self, text=nmapl[6], font=('Helvetica', 10), anchor='w')
                    lbl6.grid(row=14, column=4, sticky='we')
                except:
                    tkbox.showerror("Crawler", "Check if is a valid name and url!")
            else:
                tkbox.showerror("Crawler", "Insert a valid name and url!")


# Sniffer
class frameSniffer(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        # Logo
        img = PIL.Image.open("img/bitproof.png")
        logo = PIL.ImageTk.PhotoImage(img)
        lblLogo = tk.Label(self, image=logo, bg='#404040')
        lblLogo.img = logo
        lblLogo.grid(rowspan=2, column=0)

        # Title
        lblTitle = tk.Label(self, text="BitProof v" + version, font=('Helvetica', 25), bg='#404040', fg='#146C27', width=30,
                            height=2, anchor='w', padx=50, pady=2)
        lblTitle.grid(row=0, column=1, columnspan=7, sticky='we')

        # Running OS
        if os.name == "nt":
            opsys = "Windows 10"
        else:
            opsys = "Linux"

        if sys.maxsize > 2 ** 32:
            bit = " x64 bit"
        else:
            bit = " x32 bit"
        osys = opsys + bit + " GNU GPL Licences 2018"

        lblOS = tk.Label(self, text=osys, font=('Helvetica', 12), bg='#404040', fg='#146C27', width=30, height=2,
                         anchor='w', padx=50)
        lblOS.grid(row=1, column=1, columnspan=7, sticky='we')

        # Crawler
        imgC = PIL.Image.open("img/crawl.png")
        logoC = PIL.ImageTk.PhotoImage(imgC)
        btnCrawler = tk.Button(self, image=logoC, bg='#404040', width=15, height=100, padx=4, relief=GROOVE,
                               command=lambda: controller.show_frame("frameCrawler"))
        btnCrawler.img = logoC
        btnCrawler.grid(row=2, column=0, rowspan=4, sticky='we')

        # Sniffer
        imgS = PIL.Image.open("img/sniff.png")
        logoS = PIL.ImageTk.PhotoImage(imgS)
        btnSniffer = tk.Button(self, image=logoS, bg='#1E90FF', width=15, height=100, padx=4, relief=GROOVE,
                               command=lambda: controller.show_frame("frameSniffer"))
        btnSniffer.img = logoS
        btnSniffer.grid(row=6, column=0, rowspan=4, sticky='we')

        # nt clean up
        if os.name == "nt":
            imgC = PIL.Image.open("img/clean.png")
            logoC = PIL.ImageTk.PhotoImage(imgC)
            btnClean = tk.Button(self, image=logoC, bg='#404040', width=12, height=100, padx=4, relief=GROOVE,
                                 command=lambda: controller.show_frame("frameClean"))
            btnClean.img = logoC
            btnClean.grid(row=10, column=0, rowspan=4, sticky='we')

        lblSpace = tk.Label(self, bg='#404040', fg='#146C27', height=12)
        lblSpace.grid(row=14, column=0, rowspan=6, sticky='we')

        imgStart = PIL.Image.open("img/start.png")
        logoStart = PIL.ImageTk.PhotoImage(imgStart)
        btnStart = tk.Button(self, image=logoStart, relief=GROOVE,
                             command=lambda: sniffer(self, True))
        btnStart.img = logoStart

        imgStop = PIL.Image.open("img/stop.png")
        logoStop = PIL.ImageTk.PhotoImage(imgStop)
        btnStop = tk.Button(self, image=logoStop, relief=GROOVE,
                             command=lambda: sniffer(self, False))
        btnStop.img = logoStop

        imgGoDir = PIL.Image.open("img/more.png")
        logoGoDir = PIL.ImageTk.PhotoImage(imgGoDir)
        btnGoDir = tk.Button(self, image=logoGoDir, relief=GROOVE,
                             command=lambda: os.startfile(os.path.abspath("") + "\capture"))
        btnGoDir.img = logoGoDir

        btnStart.grid(row=3, column=2, sticky='we')
        btnStop.grid(row=3, column=4, sticky='we')
        btnGoDir.grid(row=3, column=6, sticky='we')

        # code..

        # Scroll bar
        self.scrollbar_V = tk.Scrollbar(self)
        self.scrollbar_V.grid(row=4, column=7, rowspan=12, sticky=N+S+W)

        # Listbox
        self.sniff = tk.Listbox(self, height=23, yscrollcommand=self.scrollbar_V.set)
        self.sniff.grid(row=4, column=2, rowspan=12, columnspan=5, sticky='we')

        self.scrollbar_V.config(command=self.sniff.yview)

        self.sniff.insert(0, "Nr                        IP Destinatario                        IP Sorgente"
                             "                        Protocollo ")

        NPkt = 0
        global NPkt

        # Method for sniffing all the LAN packet
        def sniffer(self, flag):
            global loop
            global NPkt
            np = NPkt
            try:
                if flag is True:
                    dest_mac, src_mac, eth_proto, version, dest_ip, src_ip, proto, TTL, checksum, flags, offset, ID, \
                    totalLength, TOS, IHL, data = runSniff(pc, decode)

                    writeResult(dest_mac, src_mac, eth_proto, version, dest_ip, src_ip, proto, TTL, checksum, flags,
                                offset, ID, totalLength, TOS, IHL, data, project_dir, stFormatted, np)

                    self.sniff.insert(END, str(np) + "                        " + str(dest_ip) +
                                      "                        " + str(src_ip) + "                        "
                                      + str(proto))
                    self.sniff.update_idletasks()

                    self.sniff.see("end")
                    np = np +1
                    NPkt = np
                    loop = self.after(100, sniffer, self, True)
                else:
                    loop = self.after_cancel(loop)
            except KeyboardInterrupt:
                nrecv, ndrop, nifdrop = pc.stats()
                print('\n%d packets received by filter' % nrecv)
                print('%d packets dropped by kernel' % ndrop)
            except:
                tkbox.showerror("Sniffer", "Error on directory! \n\nRestart program")

# Clean
class frameClean(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        # Logo
        img = PIL.Image.open("img/bitproof.png")
        logo = PIL.ImageTk.PhotoImage(img)
        lblLogo = tk.Label(self, image=logo, bg='#404040')
        lblLogo.img = logo
        lblLogo.grid(rowspan=2, column=0)

        # Title
        lblTitle = tk.Label(self, text="BitProof v" + version, font=('Helvetica', 25), bg='#404040', fg='#146C27', width=30,
                            height=2, anchor='w', padx=50, pady=2)
        lblTitle.grid(row=0, column=1, columnspan=7, sticky='we')

        # Running OS
        if os.name == "nt":
            opsys = "Windows 10"
        else:
            opsys = "Linux"

        if sys.maxsize > 2 ** 32:
            bit = " x64 bit"
        else:
            bit = " x32 bit"
        osys = opsys + bit + " GNU GPL Licences 2018"

        lblOS = tk.Label(self, text=osys, font=('Helvetica', 12), bg='#404040', fg='#146C27', width=30, height=2,
                         anchor='w', padx=50)
        lblOS.grid(row=1, column=1, columnspan=7, sticky='we')

        # Crawler
        imgC = PIL.Image.open("img/crawl.png")
        logoC = PIL.ImageTk.PhotoImage(imgC)
        btnCrawler = tk.Button(self, image=logoC, bg='#404040', width=15, height=100, padx=4, relief=GROOVE,
                               command=lambda: controller.show_frame("frameCrawler"))
        btnCrawler.img = logoC
        btnCrawler.grid(row=2, column=0, rowspan=4, sticky='we')

        # Sniffer
        imgS = PIL.Image.open("img/sniff.png")
        logoS = PIL.ImageTk.PhotoImage(imgS)
        btnSniffer = tk.Button(self, image=logoS, bg='#404040', width=15, height=100, padx=4, relief=GROOVE,
                               command=lambda: controller.show_frame("frameSniffer"))
        btnSniffer.img = logoS
        btnSniffer.grid(row=6, column=0, rowspan=4, sticky='we')

        # nt clean up
        if os.name == "nt":
            imgC = PIL.Image.open("img/clean.png")
            logoC = PIL.ImageTk.PhotoImage(imgC)
            btnClean = tk.Button(self, image=logoC, bg='#1E90FF', width=12, height=100, padx=4, relief=GROOVE,
                                 command=lambda: controller.show_frame("frameClean"))
            btnClean.img = logoC
            btnClean.grid(row=10, column=0, rowspan=4, sticky='we')

        lblSpace = tk.Label(self, bg='#404040', fg='#146C27', height=12)
        lblSpace.grid(row=14, column=0, rowspan=6, sticky='we')


        # code..
        btnGoClean = tk.Button(self, text="Clean", font=('Helvetica', 12), relief=GROOVE, command=lambda: clean())
        btnGoDefrag = tk.Button(self, text="Defrag", font=('Helvetica', 12), relief=GROOVE, command=lambda: defrag())

        btnGoClean.grid(row=4, column=2, sticky='we')
        btnGoDefrag.grid(row=8, column=2, sticky='we')

        # Method for cleaning pc hdd
        def clean():
            s, output, err = mainClean()
            if err:
                tkbox.showerror("Clean", "Error" + "\n" + str(s) + "\n" + str(output))
            else:
                tkbox.showinfo("Clean", str(s) + "\n" + str(output))

        def defrag():
            s, output, err = mainDefrag()
            if err:
                tkbox.showerror("Defrag", "Error" + "\n" + str(s) + str(output))
            else:
                tkbox.showinfo("Defrag", str(s) + "\n" + str(output))

if __name__ == "__main__":
    app = SampleApp()
    app.mainloop()
