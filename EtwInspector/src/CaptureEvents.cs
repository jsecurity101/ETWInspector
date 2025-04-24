using EtwInspector.Provider.Enumeration;
using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace EtwInspector.Capture
{
    public class EtwCaptureUtilities
    {
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_OUTOFMEMORY = 14;
        public const byte WNODE_FLAG_TRACED_GUID = 0x020;
        public const uint EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001;
        public const uint EVENT_TRACE_CONTROL_STOP = 0x00000001;
        public const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct WNODE_HEADER
        {
            public uint BufferSize;
            public uint ProviderId;
            public ulong HistoricalContext;
            public ulong TimeStamp;
            public Guid Guid;
            public uint ClientContext;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_TRACE_PROPERTIES
        {
            public WNODE_HEADER Wnode;
            public uint BufferSize;
            public uint MinimumBuffers;
            public uint MaximumBuffers;
            public uint MaximumFileSize;
            public uint LogFileMode;
            public uint FlushTimer;
            public uint EnableFlags;
            public int AgeLimit;
            public uint NumberOfBuffers;
            public uint FreeBuffers;
            public uint EventsLost;
            public uint BuffersWritten;
            public uint LogBuffersLost;
            public uint RealTimeBuffersLost;
            public IntPtr LoggerThreadId;
            public uint LogFileNameOffset;
            public uint LoggerNameOffset;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint ControlTrace(
            ulong SessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string SessionName,
            IntPtr Properties,
            uint ControlCode);
    }

    /// <summary>
    /// <para type="synopsis">Start-EtwCapture creates a trace session</para>
    /// <para type="description"> Start-EtwCapture creates a trace session</para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> $TraceSession = Start-EtwCapture -ProviderGuids "70EB4F03-C1DE-4F73-A051-33D13D5413BD" -TraceName EtwTest -OutputFilePath c:\etwcapture.xml</para>
    /// </example>
    [Cmdlet(VerbsLifecycle.Start, "EtwCapture")]
    [OutputType(typeof(TraceEventSession))]
    public class StartEtwCaptureCommand : PSCmdlet
    {
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string[] ProviderGuids { get; set; }

        [Parameter(Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string TraceName { get; set; }

        [Parameter(Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string OutputFilePath { get; set; }

        [Parameter(Mandatory = false)]
        public ulong Keywords { get; set; } = ulong.MaxValue;

        protected override void ProcessRecord()
        {
            try
            {
                var session = new TraceEventSession(TraceName, OutputFilePath);

                if (ProviderGuids != null)
                {
                    foreach (string providerName in ProviderGuids)
                    {
                        try
                        {
                            string formattedProviderName = providerName;
                            if (!providerName.StartsWith("{") || !providerName.EndsWith("}"))
                            {
                                string guidWithoutBraces = providerName.Trim('{', '}');
                                formattedProviderName = "{" + guidWithoutBraces + "}";
                            }

                            Guid providerGuid = new Guid(formattedProviderName);
                            session.EnableProvider(providerGuid, TraceEventLevel.Verbose, Keywords);
                        }
                        catch (FormatException)
                        {
                            WriteWarning($"Could not parse '{providerName}' as a GUID.");
                        }
                        catch (Exception ex)
                        {
                            WriteWarning($"Failed to enable provider '{providerName}': {ex.Message}");
                        }
                    }
                }
                WriteObject(session);
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "StartEtwCaptureError",
                    ErrorCategory.OperationStopped,
                    null));
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Stop-EtwCapture stops a trace session</para>
    /// <para type="description"> Stop-EtwCapture stops a trace session</para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> $TraceSession | Stop-EtwCapture </para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Stop-EtwCapture -TraceName EtwTest </para>
    /// </example>
    [Cmdlet(VerbsLifecycle.Stop, "EtwCapture")]
    public class StopEtwCaptureCommand : Cmdlet
    {
        [Parameter(ValueFromPipeline = true)]
        public TraceEventSession Session { get; set; }

        [Parameter()]
        public string TraceName { get; set; }


        protected override void ProcessRecord()
        {
            try
            {
                if (Session != null)
                {
                    StopTraceSessionViaSession(Session);
                }
                else if (!string.IsNullOrEmpty(TraceName))
                {
                    StopTraceSessionTraceName(TraceName);
                }
                else
                {
                    WriteWarning("No session or trace name provided.");
                }
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "StopEtwCaptureError",
                    ErrorCategory.OperationStopped,
                    null));
            }

        }

        private void StopTraceSessionViaSession(TraceEventSession Session)
        {
            try
            {
                if (Session == null)
                {
                    WriteWarning("Session parameter is null.");
                    return;
                }

                string sessionName = Session.SessionName ?? "(unnamed)";

                Session.Dispose();

                WriteObject($"ETW capture '{sessionName}' stopped.");
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "StopEtwCaptureError",
                    ErrorCategory.OperationStopped,
                    null));
            }
        }

        private void StopTraceSessionTraceName(string TraceName)
        {
            IntPtr propertiesPtr = IntPtr.Zero;

            try
            {
                uint bufferSize = (uint)Marshal.SizeOf<EVENT_TRACE_PROPERTIES>() + 2048;

                propertiesPtr = Marshal.AllocHGlobal((int)bufferSize);
                if (propertiesPtr == IntPtr.Zero)
                {
                    WriteError(new ErrorRecord(
                        new OutOfMemoryException("Failed to allocate memory for ETW properties"),
                        "ETWStopError",
                        ErrorCategory.ResourceUnavailable,
                        null));
                    return;
                }

                for (int i = 0; i < bufferSize; i++)
                {
                    Marshal.WriteByte(propertiesPtr, i, 0);
                }

                EVENT_TRACE_PROPERTIES properties = new EVENT_TRACE_PROPERTIES
                {
                    Wnode = new WNODE_HEADER
                    {
                        BufferSize = bufferSize
                    },
                    LoggerNameOffset = (uint)Marshal.SizeOf<EVENT_TRACE_PROPERTIES>()
                };

                Marshal.StructureToPtr(properties, propertiesPtr, false);

                uint status = EtwCaptureUtilities.ControlTrace(
                    0,
                    TraceName,
                    propertiesPtr,
                    EtwCaptureUtilities.EVENT_TRACE_CONTROL_STOP);

                if (status != 0)
                {
                    Exception exception = new System.ComponentModel.Win32Exception((int)status);
                    WriteError(new ErrorRecord(
                        exception,
                        "ETWStopError",
                        ErrorCategory.OperationStopped,
                        null));
                }
                else
                {
                    WriteObject($"ETW capture '{TraceName}' stopped.");
                }
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "StopEtwCaptureError",
                    ErrorCategory.OperationStopped,
                    null));
            }
            finally
            {
                if (propertiesPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(propertiesPtr);
                }
            }
        }
    }
}