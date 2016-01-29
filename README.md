# Windows-Debugger-and-Dissasembler
Advanced Windows 32-bit debugger with several diferent functions to aid in static analysis, malware analysis, and computer forensics. 
Some of the debugger functions include setting breakpoints, crash mode, and veiwing different registers. 
This tool can also completely dissasemble an executable, inject shellcode and DLL's into procesess, monitor process creation, directories, and files.
The GitHub includes the debugger, a test executable (that crashes as well), and a test DLL for injection. Everything can run on Windows 7-10.
# Overview of Funtions:

![Alt text](images/img1.PNG?raw=true "Screenshot")
# Main Debugger
The main window `^shown above^` contains all the features. To get started, select `File-Attach` and enter a PID to attach to.
Launching executables is also possible`File-Open`, but most of the debugging features don't support it, so just stick with attaching.
When ready, just hit `Start` and whatch the debugger work. The debugger is currently in `Default` mode. The first output is DLL's the executable is loading, and then debugging codes:

# Breakpoints
![Alt text](images/imgBreakPoints.PNG?raw=true "Screenshot")
For adding breakpoints, before the debugger is launched, edit the `BreakPoints.txt` file. this file must be in the same directory as the debugger if you want to use them.
The file contains something like this:

```
msvcrt.dll, printf
msvcrt.dll, strncpy
msvcrt.dll, sprintf
msvcrt.dll, vsprintf
```
To add breakpoints, add the DLL its found in, and then the function. To set what a breakpoint does, go to `Breakpoints-When a breakpoint is hit` and select an option.
The options avalible are to: `Just say Breakpoint Hit` which does what is says, `SEH Unwind` which shows the last lines of the SEH handler, `Stack unwind` which unwinds and displays the stack memory, `Disassem Around` which disassembles 10 instructions around the breakpoint, and last `All of the above plus extra` which shows everything just mentioned plus register states. Picture below:
![Alt text](images/imgBreakpoint2.PNG?raw=true "Screenshot")
# Crash mode
![Alt text](images/imgCrashmode.PNG?raw=true "Screenshot")
Crash mode detects `exception_debug_event`, determines the cause of the crash, and prints tons of output.
# Created Files Mode
Hooks several Windows functions and prints files made, deleted, or modified.
# Process and File Monitoring
`Monitoring-File` starts monitoring Windows `tmp` directories and tryes to dump the file contents. `Monitoring-Procesess` monitors created procesess and prints info on them. `Monitoring-List Procesess` list current procesess and PID's (for attaching)

File monitoring while loading Arduino:
![Alt text](images/imgFilemon.PNG?raw=true "Screenshot")
# Injection
Shellcode and DLL injection is also possible:
![Alt text](images/imgDllinjection.PNG?raw=true "Screenshot")
![Alt text](images/imgShellcode.PNG?raw=true "Screenshot")
# Disassembly
Select `File-open` then `Debugger-disassemble` to disassemble the executable:
![Alt text](images/img2.PNG?raw=true "Screenshot")
# Options
`Export` exports anything in the main text box to a file in the current directory. `Clear` clears the screen. `Colors off` turns colors off.
# Other files?
`BreakPoints.txt`: The file containing breakpoints.

`Buffer_overflow.exe`: A test exe, try attaching to it in crash mode!

`TestDLL.dll`: DLL to test with the dll injection feature.
# Problems
If you are experiencing crashes, try turning the color option off (`Options-Colors off`)
