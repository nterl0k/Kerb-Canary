# Kerb-Canary
A powershell script to enumerate logon sessions for Kerberos tickets with abnormal time-to-live(TTL) or commonly exploited weak ciphers (RC4) and then report on them through various means. The script also has the ability to purge any logon sessions detected with either of the above attributes.

Since this script needs a high level of administrative access to use WMI/Klist functions, it's best run from a scheduled task with local system authority. It can however be run interactively by a local user.

### Description
A probably over complicated script to enumerate the kerberos objects on a windows device then parse through each object looking for abnormal TTL tickets (Golden/Silver) and/or tickets requested with RC4 ciphers. Multiple (or none) reporting options available. Best results are probably going to come from running as System via schedule task or as a high level administrator.

### Function Parameters

- ExpireTime:(Default - 10hr) 
  - This will set the time window for TGS/TGT ticket expiration. Please change as needed.
- ReportLevel:(Default - "Alert") 
  - This option will tell the script which level of detection should be reported. It is set by default to "Alert" level events (bad TTL) which should reduce false positives/noise. Set differently to gain more logging.
- ResponseLevel:(Default "None")
  - This will signal the script to remove any logon sessions found with any conditions in the "Warning" or "Alert" categories. Use with caution as this may impact device/user when active.
- VerboseUp:
  - The will signal the script to dump results of it's run to the screen afterwards, good for debugging.


### Reporting Parameters 
- EventLog:(Default - Off)
  - Enable to write events to the Windows event log. 
  - This defaults to a custom log named "Kerb-Canary", this can easily be changed in the script to another log file. Running as administrator/system is recommended. 
- Syslog:(Default - Off) 
  - Enable to send logs via syslog output.
    - SyslogServer: Configure the syslog destination with this, accepts IPv4 or hostname.
    - SyslogPort: Configure the syslog server port with this.        
- Flatfile:(Default - Off) 
  - Enable to output to csv flatfile.
    - FileDir: Specify file name\directory here.

### Examples
C:\PS>./Kerb-Canary.ps1 
This runs the command in default view results only mode. 

C:\PS>./Kerb-Canary.ps1 -ReportLevel Info -VerboseUp
This runs the command to show all detections "Info" type and above, then dumps detailed output to the screen at the end.

C:\PS>./Kerb-Canary.ps1 -ReportLevel Warning -Syslog -SyslogServer 10.2.3.4 -SyslogPort 514
This runs the command to show all detections "Warning" type and above, then sends the results to the indicated syslog server/port.
