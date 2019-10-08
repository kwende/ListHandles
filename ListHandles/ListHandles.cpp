// ListHandles.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <io.h>
#include <shlwapi.h>

typedef struct _SYSTEM_HANDLE
{
	DWORD       dwProcessId;
	BYTE		bObjectType;
	BYTE		bFlags;
	WORD		wValue;
	PVOID       pAddress;
	DWORD GrantedAccess;
}SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	DWORD         dwCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION, ** PPSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


int main()
{
	FILE* dirFile = NULL; 
	HANDLE handle = (HANDLE)_get_osfhandle(_fileno(dirFile));
	/*OCVRecorderNative::ListOwnersForThisHandle((HANDLE)handle);*/
	POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(1024);
	ULONG actualLength = 0;
	NTSTATUS status = NtQueryObject(
		handle, // handle
		(OBJECT_INFORMATION_CLASS)1, // object name information
		objectTypeInfo, // the name buffer
		1024, // the size of the name buffer
		&actualLength // returned length of the object. 
	);

	PSYSTEM_HANDLE_INFORMATION pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(0x10000);
	int size = 0x10000;

	int currentProcessId = ::GetCurrentProcessId();
	for (;;)
	{
		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)16, // handle information
			pHandleInfo, // structure to fill. 
			size, // size allocated to structure
			&actualLength // actual length given to structure. 
		);

		if (NT_SUCCESS(status) && pHandleInfo)
		{
			HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
			if (hNtdll)
			{
				_NtDuplicateObject duplicateObject = (_NtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");

				if (duplicateObject)
				{
					for (int c = 0; c < pHandleInfo->dwCount; c++)
					{
						SYSTEM_HANDLE handle = pHandleInfo->Handles[c];
						int procId = handle.dwProcessId;

						if (procId != currentProcessId)
						{
							HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, procId);

							if (hProcess != INVALID_HANDLE_VALUE && hProcess > 0)
							{
								HANDLE copiedHandle;
								status = duplicateObject(
									hProcess, // owning proces
									(HANDLE)handle.wValue, // its handle to duplicate
									GetCurrentProcess(), // my process
									&copiedHandle, // my handle
									0, 0, 0);

								if (NT_SUCCESS(status))
								{
									POBJECT_TYPE_INFORMATION otherObjectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(1024);

									// get the type first. 
									actualLength = 0;
									status = NtQueryObject(
										copiedHandle, // handle
										(OBJECT_INFORMATION_CLASS)2, // object name information
										otherObjectTypeInfo, // the name buffer
										1024, // the size of the name buffer
										&actualLength // returned length of the object. 
									);
									if (NT_SUCCESS(status)
										&& otherObjectTypeInfo->Name.Length > 0 &&
										StrCmpW(L"File", otherObjectTypeInfo->Name.Buffer) == 0)
									{
										// then query the name
										actualLength = 0;
										status = NtQueryObject(
											copiedHandle, // handle
											(OBJECT_INFORMATION_CLASS)1, // object name information
											otherObjectTypeInfo, // the name buffer
											1024, // the size of the name buffer
											&actualLength // returned length of the object. 
										);
										if (NT_SUCCESS(status) &&
											otherObjectTypeInfo->Name.Length > 0 &&
											StrCmpW(otherObjectTypeInfo->Name.Buffer, objectTypeInfo->Name.Buffer) == 0)
										{
											// found another process with this same handle open. 
											break;
										}
										else
										{
											if (StrStrW(otherObjectTypeInfo->Name.Buffer, L".ocv"))
											{
												OutputDebugStringW(otherObjectTypeInfo->Name.Buffer);
											}
										}
									}
									::CloseHandle(copiedHandle);
									free(otherObjectTypeInfo);
								}
								CloseHandle(hProcess);
							}
						}
					}
				}
			}
		}
		else
		{
			free(pHandleInfo);
			size = actualLength + 5000;
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);

			//status = NtQuerySystemInformation(
			//    (SYSTEM_INFORMATION_CLASS)16, // handle information
			//    pHandleInfo, // structure to fill. 
			//    size, // size allocated to structure
			//    &actualLength // actual length given to structure. 
			//);
		}
	}
	free(pHandleInfo);

	printf("%s, %d, %d\n", objectTypeInfo->Name, pHandleInfo->dwCount, status);
	_close((int)handle);
}
