# Dynatrace OneAgent SSL certificate check plugin

This is a Dynatrace OneAgent plugin for checking and verifying SSL/TLS certificate validity for services running on hosts monitored by OneAgent. OneAgent can be deployed in both full-stack and cloud intrastructore mode. This plugin sends informational and error events if server certificate used by a service is about to expire.

# Features

- Port scope filters (inclusive / exclusive range) - only services with port numbers in the inclusive range and outside the exclusive range are checked.
- Configurable expiry time information and error event - you can configure when to send events prior to certificate expiration.
- Certificate metadata - adds certificate information to process group instance metadata
- Support for SNI - you can supply additional FQDNs to be checked

# Installation

1. Download the release zip file from the [releases] page named custom.python.sslcertcheck_plugin.zip.
2. Upload the zip file to your Dynatrace tenant in Settings > Monitoring > Monitored technologies > Custom plugins and choose Upload plugin. More information is available in  [Dynatrace help](https://www.dynatrace.com/support/help/shortlink/plugins-python#upload-your-custom-plugin)
3. Unzip the zip file on OneAgents into /opt/dynatrace/oneagent/plugin_deployment directory on agents or 
4. OneAgents with the plugin deployed will discover certificates within few minutes. Discovery events can be seen in the events area at the host level and process group level.

# Configuration

Following options can be set in the tenant:

| Setting | Description | Default value | 
| ------- | ----------- | --------------| 
| Info event (days before expiration) | Number of days before an informational event is sent for the process group about certificate expiration. | 7 |
| Error event (days before expiration) | Number of days before an error event is sent for the process group about certificate expiration. | 1 |
| Port range to include | Port range to include in the check, separated by semicolon | 443;1024-65535 |
| Port range to exclude" | Port range to exclude in the check, separated by semicolon |  |
| Show certificate info in metadata | Publish certificate info in the process group metadata, works only with recent OneAgents | true | 
| Interval between checks (hours) | Interval between checks on each host in hours | 4 |
| Additional hostnames to check (SNI) | Additional hostnames to use when Server Name Indication is used. This allows checking of services using multiple certificates for a single TLS port. | | 

# Troubleshooting

For troubleshooting check OneAgent plugin engine log.

# Limitations

- Opened TCP port bindings are retrieved from OneAgent and only local TCP ports are checked. Listening IP address is provided by OneAgent. Currently OneAgent supplies 127.0.0.1 as the listening IP address regardless of the actual TCP port binding.
- Certificate metadata information may not show up correctly in the process group metadata for OneAgent 1.177 - 1.183