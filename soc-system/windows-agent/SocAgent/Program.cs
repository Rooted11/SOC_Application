using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SocAgent.Configuration;
using SocAgent.Logging;
using SocAgent.Services;

var host = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "SOC Log Collector";
    })
    .ConfigureAppConfiguration((context, config) =>
    {
        config.SetBasePath(AppContext.BaseDirectory);
        config.AddJsonFile("agentsettings.json", optional: false, reloadOnChange: true);
    })
    .ConfigureServices((context, services) =>
    {
        services.Configure<AgentConfig>(context.Configuration);
        services.AddSingleton(resolver => resolver.GetRequiredService<IOptionsMonitor<AgentConfig>>().CurrentValue);
        services.AddSingleton<EventFileLogger>();
        services.AddHttpClient<LogForwarder>();
        services.AddHostedService<SocAgentService>();
    })
    .ConfigureLogging(logging =>
    {
        logging.ClearProviders();
        logging.AddConsole();
    })
    .Build();

await host.RunAsync();
