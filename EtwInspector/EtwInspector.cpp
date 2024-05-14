#include "helperFunctions.h"

int wmain(
    int argc,
    WCHAR* argv[]
)
{
    if (argc < 3) {
        PrintUsage();
        return 1;
    }

    NTSTATUS status = -1;
    std::wstring action = argv[1];
    std::wstring option = argv[2];
    std::wstring providerName, traceName, arg4;
    ULONGLONG keywords = 0;
    DWORD extendedDataValue = 0;
    std::vector<std::wstring> providerGuids;

    if (action == L"Enum")
    {
        if (argc >= 4)
        {
            providerName = argv[3];
        }
        if (argc == 5)
        {
            arg4 = argv[4];
            if (arg4 == L"ExtendedData")
            {
                extendedDataValue = 1;
            }
        }
        status = EnumerateProviders(
            option, 
            providerName, 
            extendedDataValue, 
            providerGuids
        );
        if (status != ERROR_SUCCESS) {
            std::cout << "[!] Error in Enumerating Providers" << std::endl;
        }

        if (arg4 == L"Capture")
        {
            keywords = 0xFFFFFFFFFFFFFFFF;
            std::wstring etlFileName = L"MyTraceFile.etl";
            NTSTATUS status = CaptureProviders(
                providerGuids, 
                L"EtwEnum", 
                etlFileName, 
                keywords
            );
            if (status != ERROR_SUCCESS)
            {
                std::wcerr << L"Failed to capture providers. Status: " << status << std::endl;
                return 1;
            }
        }

    }
    else if (action == L"Capture")
    {
        if (argc < 5) {
            PrintUsage();
            return 1;
        }

        providerName = argv[2];
        traceName = argv[3];
        keywords = _wcstoui64(argv[4], NULL, 16);
        std::vector<std::wstring> providerGuids;

        wprintf(L"Capturing trace for provider %s with trace name %s and keywords 0x%llX\n", providerName.c_str(), traceName.c_str(), keywords);

        status = EnumerateProviders(
            L"Capture", 
            providerName, 
            extendedDataValue, 
            providerGuids
        );
        if (status != ERROR_SUCCESS) {
            std::cout << "[!] Error in Enumerating Providers" << std::endl;
        }

        std::wstring etlFileName = L"MyTraceFile.etl";

        NTSTATUS status = CaptureProviders(
            providerGuids, 
            traceName, 
            etlFileName, 
            keywords
        );
        if (status != ERROR_SUCCESS)
        {
            std::wcerr << L"Failed to capture providers. Status: " << status << std::endl;
            return 1;
        }
    }
    else {
        wprintf(L"Invalid option");
        return 1;
    }

    return 0;
}

