# SeeNoEvil
Implementation to hide entries from the Windows Taskmanager, by hooking NtDll calls in userland.

# What am I Looking at?
This a small project I worked on when i had vacation. It is a very simple implementation of a DLL, that can be injected into
the windows task manager, to hide one (or more entries from it). This is accomplished, by hooking calls to NtDll from userland.
The Dll will catch the list of processes, that is coming from the "NtQuerySystemInformation" call.
It will look in the list for pids, that are requested to hide and will manipulate the datastructure, in a way,
that they are skipped during iteration.

# Disclaimer
This is a tool, that I created during research. Please do not use this tool with malicious intent.
