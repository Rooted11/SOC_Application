using System;
using System.Collections.Generic;

namespace SocAgent.Models;

public class SecurityEvent
{
    public int EventId { get; set; }
    public string LogName { get; set; } = string.Empty;
    public string Level { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string LocalIp { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public string MachineIp { get; set; } = string.Empty;
    public string? User { get; set; }
    public DateTime Timestamp { get; set; }
    public Dictionary<string, string> Details { get; set; } = new();
}
