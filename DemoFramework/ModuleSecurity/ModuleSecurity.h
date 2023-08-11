#pragma once
/****************************************************************
*  Author: Jordan Hause 03/21/2019
*
* Copyright (c) Demo Digital Group LLC, 2018
*
* This unpublished material is proprietary to Demo Digital Group LLC.
* All rights reserved. The methods and
* techniques described herein are considered trade secrets
* and/or confidential. Reproduction or distribution, in whole
* or in part, is forbidden except by express written permission
* of Demo Digital Group LLC.
****************************************************************/
typedef struct _PEB_LDR_DATA_DUMMY_
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} __PEB_LDR_DATA, *_PPEB_LDR_DATA;

typedef struct _LDR_MODULE_DUMMY_
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;

	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

namespace DemoFrame
{
	class Security
	{
	public:
		Security();
		Security(HMODULE);

		void Protect(HMODULE, bool, bool, bool, bool);

	private:
		PPEB GetPEB();
		void HideMod(HANDLE);
		void HideModPEB(HMODULE);
		void RemoveHeader(DWORD);
		void DestroyHeader(HMODULE);
		void HideXTA(HMODULE);

	};
}
