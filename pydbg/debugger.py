import my_debugger
from my_debugger_defines import *
from ctypes import *
import sys

debugger = my_debugger.debugger()
d = my_debugger
print "Windows Debugger by Starwarsfan2099"
print "Version 4.0"

select = raw_input("\nOpen or attach to an executable[Open/Attach]:")

try:
    if (select == "Attach"):
    
        pid = raw_input("Enter the PID of the process to attach to: ")

        debugger.attach(int(pid))

        printf = debugger.func_resolve("msvcrt.dll","printf")
        print "[*] Address of printf: 0x%08x" % printf
        debugger.bp_set_mem(printf,10)

        debugger.run()

    elif (select == "Open"):
        location = raw_input("Location of .exe to launch:")
        #location = "C:\WINDOWS\System32\calc.exe"
        debugger.load(location)
        printf = debugger.func_resolve("msvcrt.dll","printf")
        print "[*] Address of printf: 0x%08x" % printf
        debugger.bp_set_mem(printf,10)
        debugger.run()
        
    else:
        print "Is %s Open or Attach" % select



        
except KeyboardInterrupt:
    list = debugger.enumerate_threads()
# For each thread in the list we want to
# grab the value of each of the registers
    for thread in list:
        thread_context = debugger.get_thread_context(thread)
        # Now let's output the contents of some of the registers
        print "\n[*] Dumping registers for thread ID: 0x%08x" % thread
        print "[**] EIP: 0x%08x" % thread_context.Eip
        print "[**] ESP: 0x%08x" % thread_context.Esp
        print "[**] EBP: 0x%08x" % thread_context.Ebp
        print "[**] EAX: 0x%08x" % thread_context.Eax
        print "[**] EBX: 0x%08x" % thread_context.Ebx
        print "[**] ECX: 0x%08x" % thread_context.Ecx
        print "[**] EDX: 0x%08x" % thread_context.Edx
        print "[*] END DUMP"
    raw_input("[Press Enter to quit]")
    debugger.detach()
