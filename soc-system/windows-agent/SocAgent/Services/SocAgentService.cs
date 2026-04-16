using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SocAgent.Configuration;
using SocAgent.Logging;
using SocAgent.Models;

namespace SocAgent.Services;

public class SocAgentService : BackgroundService
{
    private readonly AgentConfig _config;
    private readonly LogForwarder _forwarder;
    private readonly EventFileLogger _fileLogger;
    private readonly ILogger<SocAgentService> _logger;
    private readonly List<EventLogWatcher> _watchers = new();
    private readonly Channel<SecurityEvent> _channel = Channel.CreateUnbounded<SecurityEvent>();
    private readonly string _hostname = Dns.GetHostName();
    private readonly string _localIp = GetLocalIpAddress();

    private static string GetLocalIpAddress()
    {
        try
        {
            var addresses = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            return addresses
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                ?.ToString()
                   ?? IPAddress.Loopback.ToString();
        }
        catch
        {
            return IPAddress.Loopback.ToString();
        }
    }

    public SocAgentService(
        AgentConfig config,
        LogForwarder forwarder,
        EventFileLogger fileLogger,
        ILogger<SocAgentService> logger)
    {
        _config = config;
        _forwarder = forwarder;
        _fileLogger = fileLogger;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting SOC log watcher for {Hostname}", _hostname);
        foreach (var logName in new[] { "Security", "System", "Application" })
        {
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName);
                var watcher = new EventLogWatcher(query, true, true);
                watcher.EventRecordWritten += OnEventRecord;
                watcher.Enabled = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _fileLogger.Log("error", $"Unable to monitor {logName} log", ex);
                _logger.LogError(ex, "Failed to create watcher for {LogName}", logName);
            }
        }

        try
        {
            await foreach (var payload in _channel.Reader.ReadAllAsync(stoppingToken))
            {
                await _forwarder.ForwardAsync(payload, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Event processing listener cancelled");
        }
    }

    private void OnEventRecord(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventRecord is null)
        {
            return;
        }

        try
        {
            var eventId = args.EventRecord.Id ?? 0;
            if (!_config.EnabledEventIds.Contains(eventId))
            {
                return;
            }

            var payload = BuildSecurityEvent(args.EventRecord);
            _channel.Writer.TryWrite(payload);
        }
        catch (Exception ex)
        {
            _fileLogger.Log("error", "Failed to serialize event record", ex);
            _logger.LogError(ex, "Error processing event record");
        }
        finally
        {
            args.EventRecord.Dispose();
        }
    }

    private SecurityEvent BuildSecurityEvent(EventRecord record)
    {
        var details = new Dictionary<string, string>();
        if (record.Properties is not null)
        {
            for (var i = 0; i < record.Properties.Count; i++)
            {
                var value = record.Properties[i]?.Value?.ToString() ?? string.Empty;
                details[$"Property{i}"] = value;
            }
        }

        var message = TryFormatMessage(record);

        return new SecurityEvent
        {
            EventId = record.Id ?? 0,
            LogName = record.LogName ?? "Unknown",
            Level = record.LevelDisplayName ?? record.Level?.ToString() ?? "Unknown",
            Message = message,
            Hostname = _hostname,
            LocalIp = _localIp,
            SourceIp = _localIp,
            MachineIp = _localIp,
            User = record.UserId?.Value,
            Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
            Details = details
        };
    }

    private static string TryFormatMessage(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? string.Empty;
        }
        catch
        {
            return record.ToXml();
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping SOC log watcher");
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.Enabled = false;
                watcher.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing watcher");
            }
        }

        _channel.Writer.Complete();
        await base.StopAsync(cancellationToken);
    }
}
