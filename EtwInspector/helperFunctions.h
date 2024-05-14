#pragma once
#include <windows.h>
#include <stdio.h>
#include <tdh.h>
#include <sstream>
#include <vector>
#include <iostream>

#pragma comment(lib, "tdh.lib")
using namespace std;

void PrintUsage();

NTSTATUS EnumerateProviders(
	_In_ std::wstring Option,
	_In_ std::wstring ProviderName,
	_In_ DWORD ExtendedData,
	_Out_ std::vector<std::wstring>& ProviderGuids
);

NTSTATUS GetServerFile(
	_In_ std::wstring providerGuid,
	_Out_ std::wstring& resourceFileName
);

NTSTATUS EnumerateProviderEvents(
	_In_ std::wstring provider
);

NTSTATUS GetEventMetadata(
	_In_ const TRACE_EVENT_INFO* pEventInfo
);

VOID PrintInformation(
	_In_ DWORD Type,
	_In_ std::wstring providerName,
	_In_ std::wstring providerGuid,
	_In_ std::wstring source,
	_In_ std::wstring resourceFileName
);

NTSTATUS CaptureProviders(
	_In_ const std::vector<std::wstring>& ProviderNames,
	_In_ std::wstring TraceName,
	_In_ std::wstring EtlFileName,
	_In_ ULONGLONG Keywords
);