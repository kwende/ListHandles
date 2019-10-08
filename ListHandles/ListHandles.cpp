// ListHandles.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <io.h>
#include <shlwapi.h>

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
);

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
	//HANDLE handle = (HANDLE)_get_osfhandle(_fileno(dirFile));
	/*OCVRecorderNative::ListOwnersForThisHandle((HANDLE)handle);*/
	//POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(1024);
	//ULONG actualLength = 0;
	//NTSTATUS status = NtQueryObject(
	//	handle, // handle
	//	(OBJECT_INFORMATION_CLASS)1, // object name information
	//	objectTypeInfo, // the name buffer
	//	1024, // the size of the name buffer
	//	&actualLength // returned length of the object. 
	//);
	HANDLE threadToken; 
	BOOL givenRights = OpenThreadToken(GetCurrentThread(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &threadToken); 
	DWORD lastError = GetLastError(); 
	if (lastError == ERROR_NO_TOKEN)
	{
		ImpersonateSelf(SecurityImpersonation); 
		givenRights = OpenThreadToken(GetCurrentThread(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &threadToken);
	}

	givenRights = SetPrivilege(threadToken, SE_DEBUG_NAME, TRUE);

	NTSTATUS status = 0; 
	ULONG actualLength = 0; 

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

						//https://github.com/tamentis/psutil/blob/master/psutil/arch/mswindows/process_handles.c
						//if ((handle.GrantedAccess == 0x0012019f)
						//	|| (handle.GrantedAccess == 0x001a019f)
						//	|| (handle.GrantedAccess == 0x00120189)
						//	|| (handle.GrantedAccess == 0x00100000)
						//    || (handle.GrantedAccess == 0x00120089)) {
						//	continue;
						//}
						//else
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
									//actualLength = 0;
									//status = NtQueryObject(
									//	copiedHandle, // handle
									//	(OBJECT_INFORMATION_CLASS)2, // object name information
									//	otherObjectTypeInfo, // the name buffer
									//	1024, // the size of the name buffer
									//	&actualLength // returned length of the object. 
									//);
									/*if (NT_SUCCESS(status)
										&& otherObjectTypeInfo->Name.Length > 0 &&
										StrCmpW(L"File", otherObjectTypeInfo->Name.Buffer) == 0)*/
									if(GetFileType(copiedHandle) == FILE_TYPE_DISK)
									{
										//https://github.com/giampaolo/psutil/issues/340#issuecomment-44022236
										//https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex
										CHAR szPath[1024]; 
										DWORD size = GetFinalPathNameByHandleA(
											copiedHandle,
											szPath,
											sizeof(szPath),
											FILE_NAME_NORMALIZED
										); 

										if (size != 0 && strstr(szPath, ".ocv"))
										{
											printf("%s\n", szPath); 
											/*DWORD error = GetLastError(); 
											printf("%d\n", error); */
										}
										
										//FILE_NAME_INFO* nameInfo = (FILE_NAME_INFO*)malloc(10024); 
										//BOOL success = GetFileInformationByHandleEx(
										//	copiedHandle,
										//	FILE_INFO_BY_HANDLE_CLASS::FileNameInfo,
										//	nameInfo,
										//	10024
										//); 
										//if (success)
										//{
										//	nameInfo->FileName[nameInfo->FileNameLength] = 0;
										//	nameInfo->FileName[nameInfo->FileNameLength + 1] = 0;
										//	wprintf(L"%s\n", nameInfo->FileName);
										//}
										//else
										//{
										//	DWORD error = GetLastError(); 
										//	printf("Error %d\n", error); 
										//}

										//wprintf(L"Flags: %d, Object Type: %d, Access: %x, ProcId: %d\n", 
										//	handle.bFlags, handle.bObjectType, handle.GrantedAccess, 
										//	handle.dwProcessId);
										//// then query the name
										//actualLength = 0;
										//status = NtQueryObject(
										//	copiedHandle, // handle
										//	(OBJECT_INFORMATION_CLASS)1, // object name information
										//	otherObjectTypeInfo, // the name buffer
										//	1024, // the size of the name buffer
										//	&actualLength // returned length of the object. 
										//);
										//if (NT_SUCCESS(status) &&
										//	otherObjectTypeInfo->Name.Length > 0 &&
										//	StrCmpW(otherObjectTypeInfo->Name.Buffer, objectTypeInfo->Name.Buffer) == 0)
										//{
										//	// found another process with this same handle open. 
										//	break;
										//}
										//else
										//{
											//if (StrStrW(otherObjectTypeInfo->Name.Buffer, L".ocv"))
											//{
											//	wprintf(L"%s\n", otherObjectTypeInfo->Name.Buffer); 
											//	//OutputDebugStringW(otherObjectTypeInfo->Name.Buffer);
											//}
										//}
									}
									::CloseHandle(copiedHandle);
									free(otherObjectTypeInfo);
								}
								CloseHandle(hProcess);
							}
	/*						else
							{
								DWORD dw = GetLastError(); 
								printf("Error opening process %d\n", dw); 
							}*/
						}
					}
				}
			}
			break; 
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
	printf("done."); 
	getchar(); 

	//printf("%s, %d, %d\n", objectTypeInfo->Name, pHandleInfo->dwCount, status);
	//_close((int)handle);
}

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}
//BOOL SetPrivilege(
//	HANDLE hToken,  // token handle 
//	LPCTSTR Privilege,  // Privilege to enable/disable 
//	BOOL bEnablePrivilege  // TRUE to enable. FALSE to disable 
//)
//{
//	TOKEN_PRIVILEGES tp = { 0 };
//	// Initialize everything to zero 
//	LUID luid;
//	DWORD cb = sizeof(TOKEN_PRIVILEGES);
//	if (!LookupPrivilegeValue(NULL, Privilege, &luid))
//		return FALSE;
//	tp.PrivilegeCount = 1;
//	tp.Privileges[0].Luid = luid;
//	if (bEnablePrivilege) {
//		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//	}
//	else {
//		tp.Privileges[0].Attributes = 0;
//	}
//	AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL);
//	if (GetLastError() != ERROR_SUCCESS)
//		return FALSE;
//
//	return TRUE;
//}
