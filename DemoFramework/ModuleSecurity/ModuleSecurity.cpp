#include "../Includes/Frame-Include.h"

DemoFrame::Security::Security()
{
}

DemoFrame::Security::Security(HMODULE Module)
{
}

void DemoFrame::Security::Protect(HMODULE Module, bool Hide, bool HidePEB, bool HideX, bool RemoveHeaders)
{

	if (RemoveHeaders)
	{
		RemoveHeader(reinterpret_cast <DWORD> (Module));
		DestroyHeader(Module);
	}
}

PPEB DemoFrame::Security::GetPEB()
{
#if defined(_M_X64) // x64
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

	// Process Environment Block (PEB)
	return tebPtr->ProcessEnvironmentBlock;
}



void DemoFrame::Security::RemoveHeader(DWORD Module)
{
	VMProtectBeginMutation ("FRAME_RemoveHDR");
	auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Module);

	if (!(DosHeader->e_magic == IMAGE_DOS_SIGNATURE))
		return;

	auto NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(DosHeader) + static_cast<DWORD>(DosHeader->e_lfanew));

	if (!(NtHeader->Signature == IMAGE_NT_SIGNATURE))
		return;

	if (NtHeader->FileHeader.SizeOfOptionalHeader == 0)
		return;

	DWORD oProtect;

	auto Size = NtHeader->FileHeader.SizeOfOptionalHeader;

	VirtualProtect(reinterpret_cast<LPVOID>(Module), Size, PAGE_READWRITE, &oProtect);
	RtlZeroMemory(reinterpret_cast<LPVOID>(Module), Size);
	VirtualProtect(reinterpret_cast<LPVOID>(Module), Size, oProtect, &oProtect);
	VMProtectEnd();
}

void DemoFrame::Security::DestroyHeader(HMODULE Module)
{
	VMProtectBeginMutation ("FRAME_DestroyHDR");
	auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Module);

	if (!(DosHeader->e_magic == IMAGE_DOS_SIGNATURE))
		return;

	auto NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(DosHeader) + static_cast<DWORD>(DosHeader->e_lfanew));

	if (!(NtHeader->Signature == IMAGE_NT_SIGNATURE))
		return;

	if (NtHeader->FileHeader.SizeOfOptionalHeader == 0)
		return;

	DWORD oProtect;

	auto Size = NtHeader->OptionalHeader.SizeOfHeaders;

	VirtualProtect(static_cast<LPVOID>(Module), Size, PAGE_EXECUTE_READWRITE, &oProtect);
	RtlZeroMemory(static_cast<LPVOID>(Module), Size);
	VirtualProtect(static_cast<LPVOID>(Module), Size, oProtect, &oProtect);
	VMProtectEnd();
}


