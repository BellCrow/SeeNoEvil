#include "hideEntry.h"


hideEntry::hideEntry(void* addressToHook, void* detourAddress)
{
	this->hookedAddress = addressToHook;
	this->detourAddress = detourAddress;
	this->overWrittenBytes = (byte*)calloc(OVERWRITTENBYTECOUNT, sizeof(byte));
	this->hookCode = (byte*)calloc(OVERWRITTENBYTECOUNT, sizeof(byte));
	callMutex = CreateMutex(
		nullptr,
		false,
		nullptr
		);
}


hideEntry::~hideEntry()
{
	free(overWrittenBytes);
	free(hookCode);
	CloseHandle(callMutex);
}

bool hideEntry::activateHook()
{
	byte* codeBytes = nullptr;
	//constructing the shellcode that establishes the hook
	codeBytes[0] = JMPCODE;
	*((DWORD*)(codeBytes + 1)) = (DWORD)((DWORD)hookedAddress - (DWORD)detourAddress);//relative jump calculation

	DWORD oldProtect = 0;
	//first save the old bytes, that we overwrite
	if (!VirtualProtect(hookedAddress, OVERWRITTENBYTECOUNT, PAGE_EXECUTE_READWRITE, &oldProtect))
		return false;
	if (memcpy_s(overWrittenBytes, OVERWRITTENBYTECOUNT, hookedAddress, OVERWRITTENBYTECOUNT) != 0)
		return false;

	//now set the new hook
	memcpy(hookCode, codeBytes, OVERWRITTENBYTECOUNT);
	//restore old protection
	VirtualProtect(hookedAddress, OVERWRITTENBYTECOUNT, oldProtect, nullptr);
	return true;
}

bool hideEntry::deactivateHook()
{
	DWORD oldProtect = 0;

	//make page writeable
	if (!VirtualProtect(hookedAddress, OVERWRITTENBYTECOUNT, PAGE_EXECUTE_READWRITE, &oldProtect))
		return false;
	//restore original bytes
	if (memcpy_s(hookedAddress, OVERWRITTENBYTECOUNT, overWrittenBytes, OVERWRITTENBYTECOUNT) != 0)
		return false;
	//restore old protection
	VirtualProtect(hookedAddress, OVERWRITTENBYTECOUNT, oldProtect, nullptr);
	return true;
}

HANDLE hideEntry::getMutex()
{
	return this->callMutex;
}