# ETWInspector
An Event Tracing for Windows (ETW) tool that allows you to enumerate Manifest & MOF providers, as well as collect events from desired providers. 

# Examples
```
Usage: EtwInspector.exe <Enum|Capture> <Options> [ProviderName|GUID] [TraceName|ExtendedData|Capture] [Keywords]

Arguments:
  <Enum|Capture>            Required. Specifies the mode of operation.
                            - Enum: Enumerates providers.
                            - Capture: Capture specified providers.
  <Options>                 Required when specifying Enum. Can be Manifest, MOF, or All.
  [ProviderName|GUID]       Optional for Enum. Required for Capture. Can be the provider name or a GUID value.
  [TraceName|ExtendedData|Capture]
                            Optional. Supported only if [ProviderName|GUID] is provided.
                            - If <Enum>: Can be ExtendedData or Capture.
                               - If <ExtendedData>: Returns event schema for Manifest providers.
                               - If <Capture>: Creates an event trace session off of the providers returned during enumeration.
                            -If <Capture>: TraceName specifies the name of the trace session created.
  [Keywords (Hex)]          - Optional. Supported only if <Capture> is specified. Holds the keywords for capture.

### Enumeration
Enumerates both MOF & Manifest providers and prints the output to screen. 

```
EtwInspector.exe Enum All

Provider Name: Windows Notification Facility Provider
Provider GUID: {42695762-EA50-497A-9068-5CBBB35E0B95}
Source: MOF
Resource File Name: N/A

Provider Name: Microsoft-Windows-ProcessExitMonitor
Provider GUID: {FD771D53-8492-4057-8E35-8C02813AF49B}
Source: Manifest
Resource File Name: %SystemRoot%\system32\werfault.exe

Provider Name: Microsoft-Windows-Hyper-V-Integration-RDV
Provider GUID: {FDFF33EC-70AA-46D3-BA65-7210009FA2A7}
Source: Manifest
Resource File Name: %systemroot%\system32\vmicrdv.dll

Provider Name: Microsoft-Windows-Sdbus
Provider GUID: {FE28004E-B08F-4407-92B3-BAD3A2C51708}
Source: Manifest
Resource File Name: %SystemRoot%\system32\drivers\sdbus.sys

Provider Name: Microsoft-Quic
Provider GUID: {FF15E657-4F26-570E-88AB-0796B258D11C}
Source: Manifest
Resource File Name: %WinDir%\system32\drivers\msquic.sys

Provider Name: Windows-ApplicationModel-Store-SDK
Provider GUID: {FF79A477-C45F-4A52-8AE0-2B324346D4E4}
Source: Manifest
Resource File Name: %SystemRoot%\System32\Windows.ApplicationModel.Store.dll

Provider Name: Microsoft-PerfTrack-MSHTML
Provider GUID: {FFDB9886-80F3-4540-AA8B-B85192217DDF}
Source: Manifest
Resource File Name: %SystemRoot%\system32\edgehtml.dll
```

Enumerates both MOF & Manifest providers for a provider with "Kerberos" in it. 

```
EtwInspector.exe Enum All Kerberos

Provider Name: Active Directory: Kerberos Client
Provider GUID: {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}
Source: MOF
Resource File Name: N/A

Provider Name: Security: Kerberos Authentication
Provider GUID: {6B510852-3583-4E2D-AFFE-A67F9F223438}
Source: MOF
Resource File Name: N/A

Provider Name: Microsoft-Windows-Security-Kerberos
Provider GUID: {98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}
Source: Manifest
Resource File Name: %SystemRoot%\System32\kerberos.dll
```

Enumerates manifest providers for a provider with "Kerberos" in it. 

```
EtwInspector.exe Enum Manifest Kerberos

Provider Name: Microsoft-Windows-Security-Kerberos
Provider GUID: {98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}
Source: Manifest
Resource File Name: %SystemRoot%\System32\kerberos.dll
```

Enumerates manifest providers for a provider with "Threat-Intel" in it and prints the events it supports.

```
EtwInspector.exe Enum Manifest Threat-Intel ExtendedData

Provider Name: Microsoft-Windows-Threat-Intelligence
Provider GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
Source: Manifest
Resource File Name: %SystemRoot%\system32\Microsoft-Windows-System-Events.dll

Event Name: (not available)
Event ID: 1
Event Version: 1
Event Channel: 16
Event Level: 4
Event Task: 1
Event Task Name: KERNEL_THREATINT_TASK_ALLOCVM
Event Keyword: 0x8000000000000004
Event Keyword Name: KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
Event Properties:
Property Name: CallingProcessId
Property Name: CallingProcessCreateTime
Property Name: CallingProcessStartKey
Property Name: CallingProcessSignatureLevel
Property Name: CallingProcessSectionSignatureLevel
Property Name: CallingProcessProtection
Property Name: CallingThreadId
Property Name: CallingThreadCreateTime
Property Name: TargetProcessId
Property Name: TargetProcessCreateTime
Property Name: TargetProcessStartKey
Property Name: TargetProcessSignatureLevel
Property Name: TargetProcessSectionSignatureLevel
Property Name: TargetProcessProtection
Property Name: OriginalProcessId
Property Name: OriginalProcessCreateTime
Property Name: OriginalProcessStartKey
Property Name: OriginalProcessSignatureLevel
Property Name: OriginalProcessSectionSignatureLevel
Property Name: OriginalProcessProtection
Property Name: BaseAddress
Property Name: RegionSize
Property Name: AllocationType
Property Name: ProtectionMask
```

Enumerates manifest providers for a provider with "Kerberos" in it and creates an ETW trace with the returned providers. 

```
EtwInspector.exe Enum Manifest Kerberos Capture

Provider Name: Microsoft-Windows-Security-Kerberos
Provider GUID: {98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}
Source: Manifest
Resource File Name: %SystemRoot%\System32\kerberos.dll

Type 'exit' to stop tracing and exit.
```

### Capture
Captures events that support the 0x8 keyword in the Microsoft-Windows-DotNETRuntime manifest provider. 

```
EtwInspector.exe Capture Microsoft-Windows-DotNETRuntime MyTrace 0x8

Type 'exit' to stop tracing and exit.
```

# To Do
- [ ] Add support for the enumeration of active trace sessions
- [ ] Add support for enumeration of providers based off of event values
- [ ] Add support to return the ETW provider's binary
