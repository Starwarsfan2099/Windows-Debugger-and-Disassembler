from ctypes import *

msvcrt = cdll.msvcrt

# Give the debugger time to attach, then hit a button
raw_input("Once the debugger is attached, press any key.")
msvcrt.printf("Printing...")

# Create the 5-byte destination buffer
buffer = c_char_p("AAAAA")
print buffer
# The overflow string
overflow = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# Run the overflow
msvcrt.strcpy(buffer, overflow)
print "Succsess"
