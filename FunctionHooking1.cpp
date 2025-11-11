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
