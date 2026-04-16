using System.Collections.Generic;

namespace SocAgent.Configuration;

public class AgentConfig
{
    public string ApiEndpoint { get; set; } = "http://localhost:8000/logs";
    public int PollingIntervalSeconds { get; set; } = 5;
    public IEnumerable<int> EnabledEventIds { get; set; } = new[] { 4624, 4625, 4740, 4672 };
    public int RetryCount { get; set; } = 3;
    public int RetryBackoffSeconds { get; set; } = 2;
    public string LogDirectory { get; set; } = "C:\\ProgramData\\SocAgent\\logs";
    public string AgentToken { get; set; } = string.Empty;
}
