using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

using System.Text;
using System.Text.RegularExpressions;


namespace Syslogd;

public partial class Worker(ILogger<Worker> logger) : BackgroundService
{
	private const string NAME = "syslogd";
	/*
	 * The PRI part MUST have three, four, or five characters and will be
	 * bound with angle brackets as the first and last characters.  The PRI
	 * part starts with a leading "<" ('less-than' character), followed by a
	 * number, which is followed by a ">" ('greater-than' character).  
	 */

	[GeneratedRegex("<([0-9]{1,3})>", RegexOptions.Compiled)]
	private static partial Regex MyRegex();

	private readonly Regex regex = MyRegex();

	#region Pri
	/// <summary>
	/// Facility  according to http://www.ietf.org/rfc/rfc3164.txt 4.1.1 PRI Part
	/// </summary>
	private enum FacilityEnum : int
	{
		kernel = 0, // kernel messages
		user = 1,   // user-level messages
		mail = 2,   // mail system
		system = 3, // system daemons
		security = 4,   // security/authorization messages (note 1)
		internally = 5, // messages generated internally by syslogd
		printer = 6,    // line printer subsystem
		news = 7,   // network news subsystem
		uucp = 8,   // UUCP subsystem
		cron = 9,   // clock daemon (note 2) changed to cron
		security2 = 10, // security/authorization messages (note 1)
		ftp = 11,   // FTP daemon
		ntp = 12,   // NTP subsystem
		audit = 13, // log audit (note 1)
		alert = 14, // log alert (note 1)
		clock2 = 15,    // clock daemon (note 2)
		local0 = 16,    // local use 0  (local0)
		local1 = 17,    // local use 1  (local1)
		local2 = 18,    // local use 2  (local2)
		local3 = 19,    // local use 3  (local3)
		local4 = 20,    // local use 4  (local4)
		local5 = 21,    // local use 5  (local5)
		local6 = 22,    // local use 6  (local6)
		local7 = 23,    // local use 7  (local7)
	}

	/// <summary>
	/// Severity  according to http://www.ietf.org/rfc/rfc3164.txt 4.1.1 PRI Part
	/// </summary>
	private enum SeverityEnum : int
	{
		emergency = 0,  // Emergency: system is unusable
		alert = 1,  // Alert: action must be taken immediately
		critical = 2,   // Critical: critical conditions
		error = 3,  // Error: error conditions
		warning = 4,    // Warning: warning conditions
		notice = 5, // Notice: normal but significant condition
		info = 6,   // Informational: informational messages
		debug = 7,  // Debug: debug-level messages
	}

	private struct Pri
	{
		public FacilityEnum Facility;
		public SeverityEnum Severity;
		public Pri(string strPri)
		{
			int intPri = Convert.ToInt32(strPri);
			int intFacility = intPri >> 3;
			int intSeverity = intPri & 0x7;
			this.Facility = (FacilityEnum)Enum.Parse(typeof(FacilityEnum), intFacility.ToString());
			this.Severity = (SeverityEnum)Enum.Parse(typeof(SeverityEnum), intSeverity.ToString());
		}
		public override readonly string ToString()
		{
			return string.Format("{0}.{1}", this.Facility, this.Severity);
		}
	}
	#endregion

	/// <summary>
	/// Evaluator is being used to translate every decimal Pri header in
	/// a Syslog message to an 'Facility.Severity ' string.
	/// </summary>
	/// <param name="match">Any Pri header match in a message</param>
	/// <returns>Translated decimal Pri header to 'Facility.Severity '</returns>
	private string Evaluator(Match match)
	{
		Pri pri = new (match.Groups[1].Value);

		return pri.ToString() + " ";
	}

	/// <summary>
	/// Translates Severity type to Syslog type,
	/// a little bit fuzzy because there are less EventLogEntryTypes
	/// than there are syslog Severity levels
	/// </summary>
	/// <param name="Severity">Syslog Severity level</param>
	/// <returns>translated EventLogEntryType</returns>
	private static EventLogEntryType Severity2EventLogEntryType(SeverityEnum Severity)
	{
		var eventLogEntryType = Severity switch
		{
			SeverityEnum.emergency => EventLogEntryType.Error,
			SeverityEnum.alert => EventLogEntryType.Error,
			SeverityEnum.critical => EventLogEntryType.Error,
			SeverityEnum.error => EventLogEntryType.Error,
			SeverityEnum.warning => EventLogEntryType.Warning,
			SeverityEnum.notice => EventLogEntryType.Information,
			SeverityEnum.info => EventLogEntryType.Information,
			SeverityEnum.debug => EventLogEntryType.Information,
			// ?
			_ => EventLogEntryType.Error,
		};
		return eventLogEntryType;
	}

	private static bool CheckSourceExists(string source)
	{
		if (EventLog.SourceExists(source))
		{
			EventLog evLog = new() { Source = source };
			if (evLog.Log != NAME)
				EventLog.DeleteEventSource(source);
		}

		if (!EventLog.SourceExists(source))
		{
			EventLog.CreateEventSource(source, NAME);
			EventLog.WriteEntry(source, $"Event Log Created '{NAME}'/'{source}'", EventLogEntryType.Information);
		}

		return EventLog.SourceExists(source);
	}


	/// <summary>
	/// Translates Syslog messages to Eventlog messages
	/// Using Pri part as source, and log them to Windows EventLog
	/// </summary>
	/// <param name="endPoint">IP/port number from datagram sender</param>
	/// <param name="strReceived">Syslog message</param>
	private void Log(EndPoint endPoint, string strReceived)
	{
		Pri pri = new(regex.Match(strReceived).Groups[1].Value);

		EventLogEntryType eventLogEntryType = Severity2EventLogEntryType(pri.Severity);

		string strMessage = string.Format("{0} : {1}", endPoint, regex.Replace(strReceived, Evaluator));

		if (CheckSourceExists(NAME))
			EventLog.WriteEntry(NAME, strMessage, eventLogEntryType);
	}



	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		IPEndPoint ipEndPoint = new(IPAddress.Any, 514);

		Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

		socket.Bind(ipEndPoint);

		// Recycling vars , i love it.
		EndPoint endPoint = ipEndPoint;

		// http://www.ietf.org/rfc/rfc3164.txt
		// 4.1 syslog Message Parts
		// The total length of the packet MUST be 1024 bytes or less.
		byte[] buffer = new byte[1024];

		if (logger.IsEnabled(LogLevel.Information))
		{
			logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);
		}


		while (!stoppingToken.IsCancellationRequested)
		{
			try
			{
				var srfr = await socket.ReceiveFromAsync(buffer, SocketFlags.None, endPoint);

				var intReceived = srfr.ReceivedBytes;

				var strReceived = Encoding.ASCII.GetString(buffer, 0, intReceived);

				Log(endPoint, strReceived);
			}
			catch (Exception exception)
			{
				if (CheckSourceExists(NAME))
					EventLog.WriteEntry(NAME, exception.Message, EventLogEntryType.Error);
			}

		}
	}


}
