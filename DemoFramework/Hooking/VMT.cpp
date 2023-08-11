#include "../Includes/Frame-Include.h"


DemoFrame::Hooking::VMT::VMT(): _dwClassBase(nullptr), __dwVMT(nullptr), _dwVMT(nullptr)
{
}

DemoFrame::Hooking::VMT::VMT(PDWORD* dwClassBase)
{
	Init(dwClassBase);
}

DemoFrame::Hooking::VMT::~VMT()
{
	this->Destroy();
}

DWORD DemoFrame::Hooking::VMT::AddHook(DWORD dwRedirect, UINT uiIndex)
{
	if (!__dwVMT || !_dwVMT
		//|| uiIndex > _dwVMTSize
		|| !uiIndex)
		return NULL;

	__Index.push_back(uiIndex);

	__dwVMT[uiIndex] = dwRedirect;

	return _dwVMT[uiIndex];
}

void DemoFrame::Hooking::VMT::DestroyHooks()
{
	if (!__dwVMT || !_dwVMT || !_dwVMTSize
		|| !__Index.size())
		return;

	for (auto i : __Index)
		DestroyHookExclusive(i);
}

void DemoFrame::Hooking::VMT::DestroyHookExclusive(UINT uiIndex)
{
	if (!__dwVMT || !_dwVMT || !_dwVMTSize
		|| !__Index.size())
		return;

	auto hkdIndex = std::find(__Index.begin(), __Index.end(), uiIndex);

	if (hkdIndex != __Index.end())
		__Index.erase(hkdIndex);

	__dwVMT[uiIndex] = _dwVMT[uiIndex];
}

DWORD* DemoFrame::Hooking::VMT::_VMT() const
{
	return _dwVMT;
}

DWORD DemoFrame::Hooking::VMT::_VMTAddress(UINT uiIndex) const
{
	if (!__dwVMT || !_dwVMT
		|| uiIndex > _dwVMTSize
		|| !uiIndex)
		return NULL;

	return _dwVMT[uiIndex];
}

int DemoFrame::Hooking::VMT::_VMTSize() const
{
	return int(_dwVMTSize);
}

void DemoFrame::Hooking::VMT::Destroy() const
{
	if (!_dwClassBase) return;

	*_dwClassBase = _dwVMT;
}

void DemoFrame::Hooking::VMT::SetVars(PDWORD* dwClassBase)
{
	_dwClassBase = dwClassBase;
	_dwVMT = static_cast<DWORD*>(*dwClassBase);
	_dwVMTSize = GetVMTSize(*dwClassBase);
	__dwVMT = new DWORD[_dwVMTSize * 4];
}

void DemoFrame::Hooking::VMT::SetRedirect() const
{
	DWORD oProtection;
	VirtualProtect(reinterpret_cast<void*>(__dwVMT), 4, PAGE_READWRITE, &oProtection);
	memcpy(reinterpret_cast<void*>(__dwVMT), reinterpret_cast<void*>(_dwVMT), (_dwVMTSize * 4));
	VirtualProtect(reinterpret_cast<void*>(__dwVMT), 4, oProtection, &oProtection);
}

void DemoFrame::Hooking::VMT::Init(PDWORD*& dwClassBase)
{
	SetVars(dwClassBase);

	SetRedirect();

	*dwClassBase = __dwVMT;
}

void DemoFrame::Hooking::VMT::Init(PDWORD** dwClassBase)
{
	Init(*dwClassBase);
}

DWORD DemoFrame::Hooking::VMT::GetVMTSize(DWORD* dwVMTSize)
{
	DWORD dwIndex = NULL;

	for (dwIndex = 0; dwVMTSize[dwIndex]; dwIndex++)
		if (!dwVMTSize[dwIndex])
			break;

	return dwIndex;
}
