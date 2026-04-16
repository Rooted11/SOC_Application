using System;
using System.IO;
using System.Text;
using SocAgent.Configuration;

namespace SocAgent.Logging;

public class EventFileLogger
{
    private readonly string _logFilePath;
    private readonly object _sync = new();

    public EventFileLogger(AgentConfig config)
    {
        var directory = string.IsNullOrWhiteSpace(config.LogDirectory)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SocAgent", "logs")
            : config.LogDirectory;

        Directory.CreateDirectory(directory);
        _logFilePath = Path.Combine(directory, "agent.log");
    }

    public void Log(string level, string message, Exception? exception = null)
    {
        var line = new StringBuilder();
        line.Append(DateTime.UtcNow.ToString("o"));
        line.Append(" | ");
        line.Append(level.ToUpperInvariant());
        line.Append(" | ");
        line.Append(message);
        if (exception is not null)
        {
            line.Append(" | ");
            line.Append(exception);
        }

        lock (_sync)
        {
            File.AppendAllText(_logFilePath, line + Environment.NewLine);
        }
    }
}
