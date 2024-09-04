# syslogd windows service

This windows service can be installed by the install script, open a command prompt as Administrator

> install.cmd

The service binds to all network interfaces on UDP port 514.
Make shure your firewall is open for port 514 (UDP).

Uninstalling 

> uninstall.cmd


All syslog information is logged as windows eventlog events.

