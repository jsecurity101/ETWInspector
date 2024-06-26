#pragma once
#include <windows.h>
#include <stdio.h>
#include <tdh.h>
#include <sstream>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cwchar> 
#include <locale>

#pragma comment(lib, "tdh.lib")
using namespace std;

#define MAX_GUID_SIZE 39

VOID PrintUsage(
);

NTSTATUS EnumerateProviders(
	_In_ std::wstring Option,
	_In_ std::wstring ProviderName,
	_In_ DWORD ExtendedData,
	_Out_ std::vector<std::wstring>& ProviderGuids
);

NTSTATUS GetResourceFile(
	_In_ std::wstring ProviderGuid,
	_Out_ std::wstring& ResourceFileName
);

NTSTATUS EnumerateProviderEvents(
	_In_ std::wstring Provider
);

NTSTATUS GetEventMetadata(
	_In_ const TRACE_EVENT_INFO* pEventInfo
);

VOID PrintInformation(
	_In_ DWORD Type,
	_In_ std::wstring ProviderName,
	_In_ std::wstring ProviderGuid,
	_In_ std::wstring Source,
	_In_ std::wstring ResourceFileName
);

NTSTATUS CaptureProviders(
	_In_ const std::vector<std::wstring>& ProviderNames,
	_In_ std::wstring TraceName,
	_In_ std::wstring EtlFileName,
	_In_ ULONGLONG Keywords
);