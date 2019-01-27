#pragma once
#include <Windows.h>

#define JMPCODE 0xEB
//							1 for jmp opcode
#define OVERWRITTENBYTECOUNT 1 + sizeof(void*)


class hideEntry
{
	void* hookedAddress;
	void* detourAddress;
	byte* overWrittenBytes;
	byte* hookCode;
	HANDLE callMutex;
public:

	hideEntry(void* addressToHook,void* detourAddress);
	~hideEntry();

	bool activateHook();
	bool deactivateHook();

	HANDLE getMutex();
};

