#include "workerFunctions.h"

//
// Function that prints the usage of the program
//
VOID PrintUsage(
)
{
    wprintf(L"Usage: EtwInspector.exe <Enum|Capture> <Options> [ProviderName|GUID] [TraceName|ExtendedData|Capture] [Keywords]\n\n"
        L"Arguments:\n"
        L"  <Enum|Capture>            Required. Specifies the mode of operation.\n"
        L"                            - Enum: Enumerates providers.\n"
        L"                            - Capture: Capture specified providers.\n"
        L"  <Options>                 Required when specifying Enum. Can be Manifest, MOF, or All.\n"
        L"  [ProviderName|GUID]       Optional for Enum. Required for Capture. Can be the provider name or a GUID value.\n"
        L"  [TraceName|ExtendedData|Capture]\n"
        L"                            Optional. Supported only if [ProviderName|GUID] is provided.\n"
        L"                            - If <Enum>: Can be ExtendedData or Capture.\n"
        L"                               - If <ExtendedData>: Returns event schema for Manifest providers.\n"
        L"                               - If <Capture>: Creates an event trace session off of the providers returned during enumeration.\n"
        L"                            -If <Capture>: TraceName specifies the name of the trace session created.\n"
        L"  [Keywords (Hex)]          - Optional. Supported only if <Capture> is specified. Holds the keywords for capture.\n\n"
        L"Examples:\n"
        L"  EtwInspector.exe Enum All\n"
        L"  EtwInspector.exe Enum Manifest DotNet ExtendedData\n"
        L"  EtwInspector.exe Enum Manifest DotNet Capture\n"
        L"  EtwInspector.exe Capture Microsoft-Windows-DotNETRuntime MyTrace\n"
        L"  EtwInspector.exe Capture Microsoft-Windows-DotNETRuntime MyTrace 0x8\n");
}

//
// Function to capture events from specified providers
//
NTSTATUS CaptureProviders(
    _In_ const std::vector<std::wstring>& ProviderNames,
    _In_ std::wstring TraceName,
    _In_ std::wstring EtlFileName,
    _In_ ULONGLONG Keywords
)
{
    DWORD status = ERROR_SUCCESS;
    TRACEHANDLE hSession = 0;
    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;

    // Generate a new GUID for the trace session
    GUID TraceGuid;
    if (CoCreateGuid(&TraceGuid) != S_OK)
    {
        return GetLastError();
    }

    ULONG BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + TraceName.size() * sizeof(wchar_t) + EtlFileName.size() * sizeof(wchar_t) + 2 * sizeof(wchar_t);

    // Allocate memory for the session properties
    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
    if (pSessionProperties == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }

    ZeroMemory(pSessionProperties, BufferSize);

    // Setting up the session properties
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->Wnode.Guid = TraceGuid;
    pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    pSessionProperties->MaximumFileSize = 5;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + TraceName.size() * sizeof(wchar_t);


    wchar_t* loggerName = (wchar_t*)((char*)pSessionProperties + pSessionProperties->LoggerNameOffset);
    wchar_t* logFileName = (wchar_t*)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset);

    wcscpy_s(loggerName, TraceName.size() + 1, TraceName.c_str());
    wcscpy_s(logFileName, EtlFileName.size() + 1, EtlFileName.c_str());

    status = StartTrace(
        &hSession,
        TraceName.c_str(),
        pSessionProperties
    );
    if (status != ERROR_SUCCESS)
    {
        free(pSessionProperties);
        return status;
    }

    // for loop to enable each provider in ProviderNames vector 
    for (const auto& providerName : ProviderNames)
    {
        GUID providerGuid;
        status = CLSIDFromString(
            providerName.c_str(),
            (LPCLSID)&providerGuid
        );
        if (status != NOERROR)
        {
            ControlTrace(
                hSession,
                TraceName.c_str(),
                pSessionProperties,
                EVENT_TRACE_CONTROL_STOP
            );
            free(pSessionProperties);
            return status;
        }

        status = EnableTraceEx2(
            hSession,
            &providerGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            NULL,
            Keywords,
            0,
            0,
            NULL
        );
        if (status != ERROR_SUCCESS)
        {
            ControlTrace(
                hSession,
                TraceName.c_str(),
                pSessionProperties,
                EVENT_TRACE_CONTROL_STOP
            );
            free(pSessionProperties);
            return status;
        }
    }

    // Wait for "exit" command
    std::string input;
    std::cout << "Type 'exit' to stop tracing and exit." << std::endl;
    while (true)
    {
        std::cin >> input;
        if (input == "exit")
        {
            break;
        }
    }

    // Stop the trace session via ControlTrace
    ControlTrace(
        NULL,
        TraceName.c_str(),
        pSessionProperties,
        EVENT_TRACE_CONTROL_STOP
    );

    free(pSessionProperties);
    return status;
}

//
// Function to enumerate providers
//
NTSTATUS EnumerateProviders(
    _In_ std::wstring Option,
    _In_ std::wstring ProviderName,
    _In_ DWORD ExtendedData,
    _Out_ std::vector<std::wstring>& ProviderGuids
)
{
    ProviderGuids = {};
    DWORD status = ERROR_SUCCESS;
    PROVIDER_ENUMERATION_INFO* penum = NULL;
    DWORD BufferSize = 0;
    WCHAR StringGuid[MAX_GUID_SIZE];
    std::wstring resourceFileName;

    // lowering the case of ProviderName
    std::transform(ProviderName.begin(), ProviderName.end(), ProviderName.begin(), ::tolower);

    // Leveraging the TdhEnumerateProviders API to enumerate the providers
    status = TdhEnumerateProviders(penum, &BufferSize);
    while (ERROR_INSUFFICIENT_BUFFER == status)
    {
        penum = (PROVIDER_ENUMERATION_INFO*)malloc(BufferSize);
        if (!penum)
        {
            wprintf(L"Allocation failed (size=%lu).\n", BufferSize);
            status = ERROR_OUTOFMEMORY;
            goto Exit;
        }

        status = TdhEnumerateProviders(
            penum,
            &BufferSize
        );
    }

    if (status != ERROR_SUCCESS)
    {
        wprintf(L"TdhEnumerateProviders failed with %lu.\n", status);
        goto Exit;
    }

    for (DWORD i = 0; i < penum->NumberOfProviders; i++)
    {
        std::wstring providerNameFromOffset = std::wstring((LPWSTR)((PBYTE)(penum)+penum->TraceProviderInfoArray[i].ProviderNameOffset));
        std::wstring lowerproviderNameFromOffset = providerNameFromOffset;
        std::transform(lowerproviderNameFromOffset.begin(), lowerproviderNameFromOffset.end(), lowerproviderNameFromOffset.begin(), ::tolower);
        
        HRESULT hr = StringFromGUID2(
            penum->TraceProviderInfoArray[i].ProviderGuid,
            StringGuid,
            ARRAYSIZE(StringGuid)
        );
        if (FAILED(hr))
        {
            wprintf(L"StringFromGUID2 failed with 0x%x\n", hr);
            status = hr;
            goto Exit;
        }
        std::wstring lowerStringGUID = StringGuid;
        std::transform(lowerStringGUID.begin(), lowerStringGUID.end(), lowerStringGUID.begin(), ::tolower);

        bool match = ProviderName == lowerproviderNameFromOffset || ProviderName == lowerStringGUID || lowerproviderNameFromOffset.find(ProviderName) != std::wstring::npos;
        if (Option == L"capture" && match)
        {
            ProviderGuids.push_back(StringGuid);
        }
        else if (Option == L"manifest" && penum->TraceProviderInfoArray[i].SchemaSource == 0 && match)
        {
            status = GetResourceFile(
                StringGuid,
                resourceFileName
            );

            PrintInformation(
                ExtendedData,
                providerNameFromOffset,
                StringGuid,
                L"Manifest",
                resourceFileName.c_str()
            );

            ProviderGuids.push_back(StringGuid);
        }
        else if (Option == L"mof" && penum->TraceProviderInfoArray[i].SchemaSource == 1 && match)
        {
            ProviderGuids.push_back(StringGuid);

            PrintInformation(
                0,
                providerNameFromOffset,
                StringGuid,
                L"MOF",
                L"N/A"
            );
        }
        else if ((Option == L"all") && match)
        {
            if (penum->TraceProviderInfoArray[i].SchemaSource == 0) {

                status = GetResourceFile(
                    StringGuid,
                    resourceFileName
                );
            }
            else {
                resourceFileName = L"N/A";
            }
            PrintInformation(
                ExtendedData,
                providerNameFromOffset,
                StringGuid,
                penum->TraceProviderInfoArray[i].SchemaSource ? L"MOF" : L"Manifest",
                resourceFileName.c_str()
            );

            ProviderGuids.push_back(StringGuid);
        }
    }

Exit:
    if (penum)
    {
        free(penum);
    }
    return status;
}

//
// Function to get the resource file for a provider
//
NTSTATUS GetResourceFile(
    _In_ std::wstring ProviderGuid,
    _Out_ std::wstring& ResourceFileName
)
{
    NTSTATUS status = ERROR_SUCCESS;
    ResourceFileName = L"";
    DWORD dwSize;
    HKEY hKey = NULL;
    WCHAR szResourceFileName[MAX_PATH] = { 0 };
    std::wstring fullKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + ProviderGuid;

    if (fullKey.length() > MAX_PATH)
    {
        status = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

    status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        fullKey.c_str(),
        0,
        KEY_READ,
        &hKey
    );
    if (status != ERROR_SUCCESS)
    {;
        goto Exit;
    }

    dwSize = sizeof(szResourceFileName);
    status = RegQueryValueEx(
        hKey,
        L"ResourceFileName",
        NULL,
        NULL,
        (LPBYTE)szResourceFileName,
        &dwSize
    );
    if (status == ERROR_SUCCESS);
    {
        ResourceFileName = szResourceFileName;
    }
    
Exit:
    if (hKey)
    {
		RegCloseKey(hKey);
	}
    return status;
}

//
// Function that enumerates the events for a provider
//
NTSTATUS EnumerateProviderEvents(
    _In_ std::wstring Provider
)
{
    GUID providerGuid;
    ULONG bufferSize = 0;
    TDHSTATUS status = CLSIDFromString(
        Provider.c_str(),
        &providerGuid
    );
    if (FAILED(status))
    {
        return status;
    }

    status = TdhEnumerateManifestProviderEvents(
        &providerGuid,
        NULL,
        &bufferSize
    );
    if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS)
    {
        return status;
    }

    std::vector<BYTE> eventBuffer(bufferSize);

    status = TdhEnumerateManifestProviderEvents(
        &providerGuid,
        (PPROVIDER_EVENT_INFO)eventBuffer.data(),
        &bufferSize
    );
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    PPROVIDER_EVENT_INFO pProviderEventInfo = (PPROVIDER_EVENT_INFO)eventBuffer.data();

    for (ULONG i = 0; i < pProviderEventInfo->NumberOfEvents; i++)
    {
        EVENT_RECORD eventRecord = { 0 };
        eventRecord.EventHeader.ProviderId = providerGuid;
        eventRecord.EventHeader.EventDescriptor = pProviderEventInfo->EventDescriptorsArray[i];

        bufferSize = 0;

        status = TdhGetEventInformation(
            &eventRecord,
            0,
            NULL,
            NULL,
            &bufferSize
        );
        if (status != ERROR_INSUFFICIENT_BUFFER)
        {
            return status;
        }

        std::vector<BYTE> eventInfoBuffer(bufferSize);
        PTRACE_EVENT_INFO pEventInfo = (PTRACE_EVENT_INFO)eventInfoBuffer.data();

        status = TdhGetEventInformation(
            &eventRecord,
            0,
            NULL,
            pEventInfo,
            &bufferSize
        );
        if (status != ERROR_SUCCESS)
        {
            return status;
        }

        status = GetEventMetadata(
            pEventInfo
        );
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
    }

    return ERROR_SUCCESS;
}

//
// Get the metadata for an event
//
NTSTATUS GetEventMetadata(
    _In_ const TRACE_EVENT_INFO* pEventInfo
)
{
    if (pEventInfo->EventNameOffset != 0)
    {
        wprintf(L"Event Name: %s\n", (PWCHAR)((PBYTE)pEventInfo + pEventInfo->EventNameOffset));
    }
    else {
        wprintf(L"Event Name: EventID_%u\n", pEventInfo->EventDescriptor.Id);
    }
    wprintf(L"Event ID: %u\n", pEventInfo->EventDescriptor.Id);
    wprintf(L"Event Version: %u\n", pEventInfo->EventDescriptor.Version);
    wprintf(L"Event Channel: %u\n", pEventInfo->EventDescriptor.Channel);
    wprintf(L"Event Level: %u\n", pEventInfo->EventDescriptor.Level);
    wprintf(L"Event Task: %u\n", pEventInfo->EventDescriptor.Task);
    wprintf(L"Event Task Name: %s\n", (pEventInfo->TaskNameOffset != 0) ? (PWCHAR)((PBYTE)pEventInfo + pEventInfo->TaskNameOffset) : L"(not available)");
    wprintf(L"Event Keyword: 0x%llX\n", pEventInfo->EventDescriptor.Keyword);
    wprintf(L"Event Keyword Name: %s\n", (pEventInfo->KeywordsNameOffset != 0) ? (PWCHAR)((PBYTE)pEventInfo + pEventInfo->KeywordsNameOffset) : L"(not available)");

    wprintf(L"Event Properties:\n");

    for (ULONG j = 0; j < pEventInfo->TopLevelPropertyCount; j++)
    {
        wprintf(L"Property Name: %s\n", (PWCHAR)((PBYTE)pEventInfo + pEventInfo->EventPropertyInfoArray[j].NameOffset));
    }

    wprintf(L"\n");

    return ERROR_SUCCESS;
}

//
// Function that prints the information for a provider
//
VOID PrintInformation(
    _In_ DWORD Type,
    _In_ std::wstring ProviderName,
    _In_ std::wstring ProviderGuid,
    _In_ std::wstring Source,
    _In_ std::wstring ResourceFileName
)
{
    wprintf(L"\nProvider Name: %s\n", ProviderName.c_str());
    wprintf(L"Provider GUID: %s\n", ProviderGuid.c_str());
    wprintf(L"Source: %s\n", Source.c_str());
    wprintf(L"Resource File Name: %s\n", ResourceFileName.c_str());

    if (Type == 1 && Source == L"Manifest")
    {
        EnumerateProviderEvents(
            ProviderGuid
        );
    }
}
