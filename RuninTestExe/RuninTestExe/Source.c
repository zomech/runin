

#include <windows.h>
#include <stdlib.h>


__declspec(naked) int CALLBACK wWinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR lpCmdLine,
	_In_ int nShowCmd)
{
	
	wchar_t peb[20];
	DWORD address;

	__asm {
		push eax
		mov eax, fs:[0x30]
		mov address, eax
		pop eax
	}

	wsprintfW(peb, L"0x%x", address);
	MessageBoxW(NULL, peb, L"Nice", MB_OK);

	__asm {
		
		add esp, 0x30
		leave
		ret
	}
}