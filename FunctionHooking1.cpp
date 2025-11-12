// https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html

#include <iostream>
#include <gdiplus.h>
#include <windows.h>

Gdiplus::ARGB AddColors(Gdiplus::ARGB left, Gdiplus::ARGB right);
Gdiplus::ARGB ReturnRed(Gdiplus::ARGB left, Gdiplus::ARGB right);

int main()
{

}

void InstallHook32(void* hooked, void* payload)
{
	DWORD oldProtection;

	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
	VirtualProtect(AddColors, 1024, PAGE_EXECUTE_READWRITE, &oldProtection);

	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };  // https://www.felixcloutier.com/x86/jmp

	// An offset is needed to fill the 32-bit operand of jmp. 
	// The offset in question is between the payload function and the instruction right after the JMP instruction.
	const uint32_t relativeAddress = (uint32_t)payload - ((uint32_t)hooked + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relativeAddress, 4); // Fills idx 1 to 4 in the jmpInstruction variable;

	// Effectively installs the hook (this is destructive hooking).
	memcpy(hooked, jmpInstruction, sizeof(jmpInstruction));

	return;
}


void* AllocatePageNearAddress(void* targetAddress)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;
	// i don't have a fucking clue on what happens from here

	const uintptr_t startAddress = ((uintptr_t)targetAddress) & ~(PAGE_SIZE - 1);  // Rounds down to the nearest page boundary.
	// I gotta come back to the line above and try to understand wtf is going on there.
	uintptr_t minAddress = (uintptr_t)min(startAddress - 0x7FFFFF00, (uintptr_t)sysInfo.lpMinimumApplicationAddress);
	uintptr_t maxAddress = (uintptr_t)max(startAddress + 0x7FFFFF00, (uintptr_t)sysInfo.lpMaximumApplicationAddress);

	uintptr_t startPage = (startAddress - (startAddress % PAGE_SIZE)); // Not a single clue though.

	uintptr_t pageOffset = 1;

	while(true)
	{
		uintptr_t byteOffset = pageOffset * PAGE_SIZE;
		uintptr_t highAddress = startPage + byteOffset;
		uintptr_t lowAddress = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddress > maxAddress && lowAddress < minAddress;

		if (highAddress < maxAddress)
		{
			void* outAddress = VirtualAlloc((void*)highAddress, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddress)
			{
				return outAddress;
			}
		}

		if (lowAddress > minAddress)
		{
			void* outAddress = VirtualAlloc((void*)lowAddress, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddress)
			{
				return outAddress;
			}
		}

		pageOffset++;

		if (needsExit)
			break;
	}

	return nullptr;

}
