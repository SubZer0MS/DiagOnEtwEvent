# DiagOnEtwEvent
This program will either create a memory dump or attach Time Travel Debugging tool when a specific native or managed (.NET) module (DLL) gets loaded into a process

There are times when a DLL gets loaded and unloaded so fast that we don't have time to attach a debugger (especially TTD: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview)  to it because of mostly 2 reasons:
  1. there might be multiple "worker" processes that get spawned and we don't know which one it will be (ex. WmiPrvSe.exe for WMI work)
  2. if the DLL is managed (.NET), we won't be able to get to it via PowerShell (ex. (Get-Process).Modules or Process Explorer or TaskList) because it get is actually an Assembly and it does not get loaded normally via the LDR component, but rather by the CLR (if it's not already native compiled)
  
There are a lot of situations where some .NET Assembly gets loaded and finishes in under seconds and it does not log anything in any log file or it does not throw an Exception, but rather just does not do what we expect and fails silently. In such situations, we need to understand what it does and what is going on, ideally by attaching such a cool tool as TTD (Time Travel Debugging: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview).

This tool (DiagOnEtwEvent) does have the option to create a full memory user dump as well, but it's main purpose is to be used to attach TTD to a Process when a certain DLL (especially if it's a .NET Assembly) will get loaded in order for us to record what that Process (mainly related to things that the loaded module) is doing.

NOTE: In order for this to work, this program (DiagOnEtwEvent.exe) will need to be copied in the same folder as TTTRacer.exe which is the main controller process of TTD: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview

This is very nice to have because we can add functionatlity to this (either by changing the code or by adding functionality with additional parameters) in order to be able to take such actions (ex. attach TTD tool) in many other ETW event scenarios when a specific ETW event is raised (from whichever provider we are interested in). Currently, it's using the Image load/unload (https://docs.microsoft.com/lt-lt/windows/win32/etw/image) event types from the NT Kernel Logger - here is a full list: https://docs.microsoft.com/lt-lt/windows/win32/etw/nt-kernel-logger-constants

I might refactor some of the code at some point and/or add additional functionality, depending on how much time I get to invest in this project. Currently it's exactly what I need, so no other functionality for now, hehe :D

Contributions are welcome though! :D
