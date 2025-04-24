# ETWInspector
EtwInspector is a comprehensive Event Tracing for Windows (ETW) toolkit designed to simplify the enumeration of ETW providers and trace session properties.

Developed in C#, EtwInspector is easily accessible as a PowerShell module, making it user-friendly and convenient. This tool aims to be a one-stop solution for all ETW-related tasks—from discovery and inspection to trace capturing.

## Instructions
### PowerShell Gallery
Coming soon...

### Import Directly
1. Import EtwInspector via: 
```
PS > Import-Module EtwInspector.psd1
```
You may need to go to the file and press "unblock" if you get an error about importing the module and its depedencies. 

2. Get a list of available commands within the module: 
```
PS > Get-Command -Module EtwInspector

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Get-EtwProviders                                   1.0        EtwInspector
Cmdlet          Get-EtwSecurityDescriptor                          1.0        EtwInspector
Cmdlet          Get-EtwTraceSessions                               1.0        EtwInspector
Cmdlet          Start-EtwCapture                                   1.0        EtwInspector
Cmdlet          Stop-EtwCapture                                    1.0        EtwInspector
```

### Enumeration Steps

#### ETW Providers
`Get-EtwProviders` allows a user to enumerate Manifest, MOF, and Tracelogging providers. Depending on the provider type that is being queried, some functionality is more advanced then others. 

Example 1: Enumerating Manifest/MOF providers that have "Threat" in the provider name

```
PS > $EnumProviders = Get-EtwProviders -ProviderName Threat

PS > $EnumProviders

RegisteredProviders                     TraceloggingProviders
-------------------                     ---------------------
{Microsoft-Windows-Threat-Intelligence}


PS > $EnumProviders.RegisteredProviders

providerGuid       : f4e1897c-bb5d-5668-f1d8-040f4d8dd344
providerName       : Microsoft-Windows-Threat-Intelligence
resourceFilePath   : %SystemRoot%\system32\Microsoft-Windows-System-Events.dll
schemaSource       : Manifest
eventKeywords      : {KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL, KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER,
                     KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE, KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER...}
eventMetadata      : {1, 2, 2, 2...}
securityDescriptor : EtwInspector.Provider.Enumeration.EventTraceSecurity
```

Example 2: Enumerating Manifest providers that have "ReadVm" in a property field
```
PS > $EnumProviders = Get-EtwProviders -PropertyString ReadVm

PS > $EnumProviders

RegisteredProviders                     TraceloggingProviders
-------------------                     ---------------------
{Microsoft-Windows-Threat-Intelligence}


PS > $EnumProviders.RegisteredProviders

providerGuid       : f4e1897c-bb5d-5668-f1d8-040f4d8dd344
providerName       : Microsoft-Windows-Threat-Intelligence
resourceFilePath   : %SystemRoot%\system32\Microsoft-Windows-System-Events.dll
schemaSource       : Manifest
eventKeywords      : {KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL, KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER,
                     KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE, KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER...}
eventMetadata      : {1, 2, 2, 2...}
securityDescriptor : EtwInspector.Provider.Enumeration.EventTraceSecurity
```

Example 3: Enumerating tracelogging providers that exist in kerberos.dll

```
PS > $EnumProviders = Get-EtwProviders -ProviderType TraceLogging -FilePath C:\Windows\System32\kerberos.dll

PS > $EnumProviders

RegisteredProviders TraceloggingProviders
------------------- ---------------------
{}                  EtwInspector.Provider.Enumeration.TraceLoggingSchema


PS > $EnumProviders.TraceloggingProviders

FilePath                         Providers
--------                         ---------
C:\Windows\System32\kerberos.dll {Microsoft.Windows.Security.Kerberos, Microsoft.Windows.Security.SspCommon, Microsoft.Windows.Tlg...
```

`Get-EtwTraceSessions` is also another cmdlet that allows someone to query trace sessions locally and remotely. You can query regular trace sessions, trace sessions that live in a data collector, and/or both. 


### Capture
EtwInspector also holds cmdlets, `Start-EtwCapture` and `Stop-EtwCapture` that allows a users to start and stop ETW trace sessions locally. These are fairly straight forward. Feel free to call `Get-Help Start-EtwCapture -Examples` for more details. 


## Previous Versions
If you prefer to use EtwInspector 1.0, which is written in C++ please visit the `v1.0` branch. 

## Feedback
If there are any features you would like to see, please don't hesitate to reach out. 

Thank you to the following people who were willing to test this tool and provide feedback: 
- Olaf Hartong
- Matt Graeber

## Resources/Nuget Packages:
* Fody
* Microsoft.Diagnostics.Tracing.TraceEvent
* XmlDoc2CmdletDoc

## Release Notes

v1.0.0
* Initial release of package
* Following Cmdlets: 
    * Get-EtwProviders 
    * Get-EtwSecurityDescriptor 
    * Get-EtwTraceSessions
    * Start-EtwCapture
    * Stop-EtwCapture


