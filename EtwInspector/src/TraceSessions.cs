using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Xml;
using EtwInspector.Provider.Enumeration;

namespace EtwInspector.TraceSessions
{
    public class DataCollectorSetInfo
    {
        public string CollectionName { get; set; }
        public string TraceSessionGuid { get; set; }

        public IList<ProviderInfo> Providers { get; set; }

        public string[] SessionNames { get; set; }

        public string Security { get; set; }

        public string OutputLocation { get; set; }

        public string XML { get; set; }
    }

    public class ProviderInfo
    {
        public string Guid { get; set; }

        public string DisplayName { get; set; }

        public string KeywordsAny { get; set; }

        public string KeywordsAll { get; set; }
    }

    public class EtwTraceUtilities
    {
        public const int COINIT_APARTMENTTHREADED = 0x2;

        [DllImport("ole32.dll")]
        public static extern int CoInitializeEx(IntPtr pvReserved, int dwCoInit);

        [DllImport("ole32.dll")]
        public static extern void CoUninitialize();
    }

    /// <summary>
    /// <para type="synopsis">Get-EtwTraceSessions enumerates ETW Trace Sessions</para>
    /// <para type="description"> Get-EtwTraceSessions enumerates ETW Trace Sessions and Data Collectors that have Trace Sessions. </para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> Get-EtwProviders</para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Get-EtwTraceSessions -Namespace Session -SessionName TestSession </para>
    /// </example>
    /// <example>
    /// <para> PS C:\>$Sessions = Get-EtwTraceSessions -ProviderGuid "70EB4F03-C1DE-4F73-A051-33D13D5413BD" </para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "EtwTraceSessions")]
    public class GetEtwTraceSessionsCommand : Cmdlet
    {
        [Parameter(Mandatory = false)]
        public string SessionName { get; set; }

        [Parameter(Mandatory = false)]
        public string ProviderName { get; set; }

        [Parameter(Mandatory = false)]
        public string ProviderGuid { get; set; }

        [Parameter(Mandatory = false)]
        [ValidateSet("All", "Session", "Service")]
        public string Namespace { get; set; } = "All";

        [Parameter(Mandatory = false)]
        public string Host { get; set; }
        protected override void ProcessRecord()
        {
            try
            {
                QueryDataCollectorSets(SessionName, ProviderName, Host, Namespace);
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "ErrorRetrievingSessions", ErrorCategory.NotSpecified, null));
            }
        }

        private void QueryDataCollectorSets(string sessionName, string providerName, string host, string namespaceName)
        {
            bool comInitialized = false;

            try
            {
                int hr = EtwTraceUtilities.CoInitializeEx(IntPtr.Zero, EtwTraceUtilities.COINIT_APARTMENTTHREADED);
                if (hr < 0)
                {
                    WriteWarning($"CoInitializeEx failed with 0x{hr:X}");
                    return;
                }

                comInitialized = true;

                Type dcsCollectionType = Type.GetTypeFromProgID("Pla.DataCollectorSetCollection.1");
                if (dcsCollectionType == null)
                {
                    WriteWarning("Failed to get type for Pla.DataCollectorSetCollection");
                    return;
                }

                dynamic pdcSets = Activator.CreateInstance(dcsCollectionType);

                string filter = GetNamespaceFilter(namespaceName);

                pdcSets.GetDataCollectorSets(host, filter);

                foreach (dynamic pdcSet in pdcSets)
                {
                    try
                    {
                        string name = pdcSet.Name;
                        string xml = pdcSet.Xml;

                        if (string.IsNullOrEmpty(xml))
                        {
                            WriteWarning($"Data collector set '{name}' has no XML configuration");
                            continue;
                        }

                        DataCollectorSetInfo dataCollectorSetInfo = ParseDataCollectorSetXml(name, xml);

                        List<DataCollectorSetInfo> filteredSets = FilterDataCollectorSets(new List<DataCollectorSetInfo> { dataCollectorSetInfo });

                        foreach (var dcInfo in filteredSets)
                        {
                            WriteObject(dcInfo);
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarning($"Error processing data collector set: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteWarning($"Error querying data collect: {ex.Message}");
            }
            finally
            {
                if (comInitialized)
                {
                    EtwTraceUtilities.CoUninitialize();
                }
            }
        }

        private string GetNamespaceFilter(string namespaceName)
        {
            if (string.IsNullOrEmpty(namespaceName) || namespaceName == "All")
            {
                return null;
            }

            return $"{namespaceName}\\*";
        }

        private DataCollectorSetInfo ParseDataCollectorSetXml(string name, string xml)
        {
            var providerGuids = new List<string>();
            var providerDisplayNames = new List<string>();
            var providerKeywordsAny = new List<string>();
            var providerKeywordsAll = new List<string>();
            var sessionNames = new List<string>();
            string securitySetting = "";
            string outputLocation = "";
            string traceSessionGuid = string.Empty;

            try
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xml);

                XmlNode securityNode = doc.SelectSingleNode("//DataCollectorSet/Security");
                if (securityNode != null)
                {
                    securitySetting = securityNode.InnerText;
                }

                XmlNode outputLocationNode = doc.SelectSingleNode("//DataCollectorSet/OutputLocation");
                if (outputLocationNode != null)
                {
                    outputLocation = outputLocationNode.InnerText;
                }

                XmlNodeList sessionNameNodes = doc.SelectNodes("//TraceDataCollector/SessionName");
                if (sessionNameNodes != null && sessionNameNodes.Count > 0)
                {
                    foreach (XmlNode node in sessionNameNodes)
                    {
                        if (!string.IsNullOrEmpty(node.InnerText) && !sessionNames.Contains(node.InnerText))
                        {
                            sessionNames.Add(node.InnerText);
                        }
                    }
                }

                XmlNode traceSessionGuidNode = doc.SelectSingleNode("//TraceDataCollector/Guid");
                if (traceSessionGuidNode != null)
                {
                    traceSessionGuid = traceSessionGuidNode.InnerText;
                }

                ExtractProviderInfo(doc, providerGuids, providerDisplayNames, providerKeywordsAny, providerKeywordsAll);
            }
            catch (XmlException ex)
            {
                WriteWarning($"Error parsing XML for '{name}': {ex.Message}");
            }

            var providers = new List<ProviderInfo>();
            for (int i = 0; i < providerGuids.Count; i++)
            {
                providers.Add(new ProviderInfo
                {
                    Guid = providerGuids[i],
                    DisplayName = i < providerDisplayNames.Count ? providerDisplayNames[i] : "Unknown",
                    KeywordsAny = i < providerKeywordsAny.Count ? providerKeywordsAny[i] : "Unknown",
                    KeywordsAll = i < providerKeywordsAll.Count ? providerKeywordsAll[i] : "Unknown"
                });
            }
            
            return new DataCollectorSetInfo
            {
                CollectionName = name,
                TraceSessionGuid = traceSessionGuid,
                Providers = providers,
                SessionNames = sessionNames.ToArray(),
                Security = securitySetting,
                OutputLocation = outputLocation,
                XML = xml
            };
        }

        private void ExtractProviderInfo(
            XmlDocument doc,
            List<string> providerGuids,
            List<string> providerDisplayNames,
            List<string> providerKeywordsAny,
            List<string> providerKeywordsAll)
        {
            XmlNodeList providerNodes = doc.GetElementsByTagName("TraceDataProvider");

            foreach (XmlNode providerNode in providerNodes)
            {
                XmlNode guidNode = providerNode.SelectSingleNode("Guid");
                if (guidNode != null && !string.IsNullOrEmpty(guidNode.InnerText))
                {
                    string guidText = guidNode.InnerText;
                    if (guidText.StartsWith("{") && guidText.EndsWith("}"))
                    {
                        guidText = guidText.Substring(1, guidText.Length - 2);
                    }
                    providerGuids.Add(guidText);

                    XmlNode displayNameNode = providerNode.SelectSingleNode("DisplayName");
                    string displayName = displayNameNode != null ? displayNameNode.InnerText : "Unknown";
                    providerDisplayNames.Add(displayName);

                    XmlNode keywordsAnyValueNode = providerNode.SelectSingleNode("KeywordsAny/Value");
                    if (keywordsAnyValueNode != null)
                    {
                        string keywordsAnyValue = keywordsAnyValueNode.InnerText;
                        providerKeywordsAny.Add(keywordsAnyValue);
                    }
                    else
                    {
                        providerKeywordsAny.Add("Unknown");
                    }

                    XmlNode keywordsAllValueNode = providerNode.SelectSingleNode("KeywordsAll/Value");
                    if (keywordsAllValueNode != null)
                    {
                        string keywordsAllValue = keywordsAllValueNode.InnerText;
                        providerKeywordsAll.Add(keywordsAllValue);
                    }
                    else
                    {
                        providerKeywordsAll.Add("Unknown");
                    }
                }
            }
        }

        private List<DataCollectorSetInfo> FilterDataCollectorSets(List<DataCollectorSetInfo> dataCollectorSets)
        {
            var filteredSets = new List<DataCollectorSetInfo>(dataCollectorSets);

            if (!string.IsNullOrEmpty(SessionName))
            {
                filteredSets = filteredSets.FindAll(dcs =>
                    dcs.CollectionName.IndexOf(SessionName, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (dcs.SessionNames != null && dcs.SessionNames.Any(sn =>
                        sn.IndexOf(SessionName, StringComparison.OrdinalIgnoreCase) >= 0)));
            }

            if (!string.IsNullOrEmpty(ProviderName))
            {
                filteredSets = filteredSets.FindAll(dcs =>
                    dcs.Providers != null && dcs.Providers.Any(p =>
                        p.DisplayName.IndexOf(ProviderName, StringComparison.OrdinalIgnoreCase) >= 0));
            }

            if (!string.IsNullOrEmpty(ProviderGuid))
            {
                filteredSets = filteredSets.FindAll(dcs =>
                    dcs.Providers != null && dcs.Providers.Any(p =>
                        string.Equals(p.Guid, ProviderGuid, StringComparison.OrdinalIgnoreCase)));
            }

            return filteredSets;
        }
    }
}