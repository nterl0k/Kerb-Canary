
#Param(
#Set Expiration Parameters
#Set Output parameters (CEF/Event Log)
#)

#Klist ConvertFrom-String Template
$KTGTParse = @'
#{[int]ID*:0}>	Client: {Client:Administrator} @ {ClientDomain:DOMAIN.LAN}
	Server: {Server:krbtgt/DOMAIN.LAN} @ {ServerDomain:DOMAIN.LAN}
	KerbTicket Encryption Type: {TicketEncryptionType:AES-256-TICKET}
	Ticket Flags {TicketFlags:0xabcd1234} -> {TicketFlagsEnum:flag flag flag flag} 
	Start Time: {[datetime]StartTime:1/01/1970 00:00:00} (local)
	End Time:   {[datetime]EndTime:1/01/1970 00:00:00} (local)
	Renew Time: {[datetime]RenewTime:1/01/1970 00:00:00} (local)
	Session Key Type: {SessionKeyType:AES-256-TICKET}
	Cache Flags: {CacheFlags:0x1} -> {CacheFlagsEnum:FLAGTYPE} 
	Kdc Called: {KDCCalled:2012-DC.DOMAIN.LAN}

#{[int]ID*:1}>	Client: {Client:Administrator} @ {ClientDomain:DOMAIN.LAN}
	Server: {Server:RPCSS/2012R2-MS.DOMAIN.LAN} @ {ServerDomain:DOMAIN.LAN}
	KerbTicket Encryption Type: {TicketEncryptionType:RC4-TICKET}
	Ticket Flags {TicketFlags:0xabcd1234} -> {TicketFlagsEnum:flag flag flag flag}
	Start Time: {[datetime]StartTime:1/01/1970 00:00:00} (local)
	End Time:   {[datetime]EndTime:1/01/1970 00:00:00} (local)
	Renew Time: {[datetime]RenewTime:1/01/1970 00:00:00} (local)
	Session Key Type: {SessionKeyType:RC4-TICKET}
	Cache Flags: {CacheFlags:0} 
	Kdc Called: {KDCCalled:2012-DC.DOMAIN.LAN}
'@

$KSessionParse = @'
[{[int]ID*:0}] Session {[int]SessionID:0} 0:{LogonID:0xabcd12} {Identity:Some Type\Identity-02} {AuthMethod:Negotiate}:{Interaction:Interaction}
[{[int]ID*:1}] Session {[int]SessionID:1} 0:{LogonID:0xabcd} {Identity:*} {AuthMethod:NTLM}:{Interaction:*}
'@

#Dump Current User Sessions


#Dump Current Tickets
$ktgt = Get-Content C:\Users\Admin\Desktop\klist.txt
$ksession = Get-Content C:\Users\Admin\Desktop\ksession.txt

#Parse Current Tickets
$KTGTParse = $ktgt | ConvertFrom-String -TemplateContent $KTGTParse
$KSessionParse = $ksession | ConvertFrom-String -TemplateContent $KSessionParse

#Check for Golden Tickets

$KTGTParse | Out-GridView
$KSessionParse | Out-GridView