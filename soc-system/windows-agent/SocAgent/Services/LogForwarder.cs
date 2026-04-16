using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SocAgent.Configuration;
using SocAgent.Logging;
using SocAgent.Models;

namespace SocAgent.Services;

public class LogForwarder
{
    private readonly HttpClient _httpClient;
    private readonly AgentConfig _config;
    private readonly EventFileLogger _fileLogger;
    private readonly ILogger<LogForwarder> _logger;

    public LogForwarder(HttpClient httpClient, AgentConfig config, EventFileLogger fileLogger, ILogger<LogForwarder> logger)
    {
        _httpClient = httpClient;
        _config = config;
        _fileLogger = fileLogger;
        _logger = logger;
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
    }

    public async Task<bool> ForwardAsync(SecurityEvent payload, CancellationToken cancellationToken)
    {
        var serialized = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });

        for (var attempt = 0; attempt <= _config.RetryCount; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _config.ApiEndpoint)
            {
                Content = new StringContent(serialized, Encoding.UTF8, "application/json")
            };

            if (!string.IsNullOrWhiteSpace(_config.AgentToken))
            {
                request.Headers.TryAddWithoutValidation("X-Agent-Token", _config.AgentToken);
            }

            try
            {
                var response = await _httpClient.SendAsync(request, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    _fileLogger.Log("info", $"Forwarded event {payload.EventId} to {_config.ApiEndpoint}");
                    return true;
                }

                var error = await response.Content.ReadAsStringAsync(cancellationToken);
                _fileLogger.Log("warning", $"Agent rejected event {payload.EventId}: {response.StatusCode} {error}");
                _logger.LogWarning("Server rejected log {EventId} with status {Status}: {Body}", payload.EventId, response.StatusCode, error);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _fileLogger.Log("error", $"Failed to forward event {payload.EventId} (attempt {attempt + 1})", ex);
                _logger.LogError(ex, "Failed to forward event {EventId} (attempt {Attempt})", payload.EventId, attempt + 1);
            }

            if (attempt < _config.RetryCount)
            {
                await Task.Delay(TimeSpan.FromSeconds(_config.RetryBackoffSeconds), cancellationToken);
            }
        }

        _fileLogger.Log("error", $"Exhausted retries for event {payload.EventId}");
        return false;
    }
}
