using Syslogd;

Console.WriteLine("Please run as administrator");

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = ".NET Syslogd Service";
});

builder.Services.AddHostedService<Worker>();

var host = builder.Build();

host.Run();
