<#
.SYNOPSIS
    Script to find/kill golden tickets.

.DESCRIPTION
    A probably over complicated script to enumerate the kerberos objects on a windows device
    then parse through each object looking for abnormal TTL tickets (Golden/Silver) and/or
    tickets requested with RC4 ciphers. Multiple (or none) reporting options available. Best
    results are probably going to come from running as System via schedule task or as a high 
    level administrator.

.PARAMETER ExpireTime
    (Required) This will set the time window for TGS/TGT ticket expiration. 
    Default is set to 10hrs, please change as needed.

.PARAMETER ReportLevel 
    (Optional - Default Alert) This option will tell the script which level of 
    detection should be reported. It is set by default to "Alert" level events (bad TTL)
    which should reduce false positives/noise. Set differently to gain more logging.

.PARAMETER ResponseLevel 
    (Optional - Default None) This will signal the script to remove any logon 
    sessions found with any conditions in the "Warning" or "Alert" categories. 
    Use with caution as the may impact device/user when active.

.PARAMETER VerboseUp
    The will signal the script to dump results of it's run to
    the screen afterwards, good for debugging.

.PARAMETER EventLog
    Enable writing events to the Windows event log. This defaults to the
    security log, so needs to be run as administrator/system.

.PARAMETER Syslog
    Enable syslog server logging.

.PARAMETER SyslogServer
    Configure the syslog destination with this, accepts IPv4 or hostname.

.PARAMETER SyslogPort
    Configure the syslog server port with this.        

.PARAMETER Flatfile
    Enable output to csv flatfile.

.PARAMETER FileDir
    Specify file name\directory here.

.EXAMPLE
    C:\PS>./Kerb-Canary.ps1 
            This runs the command in default view results only mode. 

.EXAMPLE
    C:\PS>./Kerb-Cabary.ps1 -ReportLevel Info -VerboseUp
            This runs the command to show all detections "Info" type and above, then dumps detailed output to the screen at the end.

.EXAMPLE
    C:\PS>./Kerb-Cabary.ps1 -ReportLevel Warning -Syslog -SyslogServer 10.2.3.4 -SyslogPort 514
            This runs the command to show all detections "Warning" type and above, then sends the results to the indicated syslog server/port.

.NOTES
    Author: Nterl0k
    Date:   March 14, 2019
    Version: Initial 1.0
        
#>
[cmdletbinding(DefaultParametersetname="All")] 
param(
    [Parameter(Mandatory=$false,ParameterSetName="All")]  
    [Parameter(HelpMessage="Please enter a TTL for kerberos tickets.")]
    [ValidateNotNullOrEmpty()]
    $ExpireTime = 10,

    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [ValidateSet("Warning","Alert","None")]
    [ValidateNotNullOrEmpty()]
    [string]$ResponseLevel = "None",

    [Parameter(Mandatory=$false,ParameterSetName="All")]  
    [Parameter(HelpMessage="Please enter a reporting output level.")]
    [ValidateSet("Info","Error","Warning","Alert")]
    [ValidateNotNullOrEmpty()]
    [string]$ReportLevel = "Alert",

    [Parameter(Mandatory=$false,ParameterSetName="All")]  
    [switch]$VerboseUp,
    
    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [Parameter(Mandatory=$false,ParameterSetName="EventLog_CFG")]
    [switch]$EventLog,

    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [Parameter(Mandatory=$false,ParameterSetName="Syslog_CFG")]
    [Switch]$Syslog,
    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [Parameter(Mandatory=$true,ParameterSetName="Syslog_CFG",HelpMessage="Please enter a syslog server.")]
    [string]$SyslogServer,
    
    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [Parameter(Mandatory=$true,ParameterSetName="Syslog_CFG",HelpMessage="Please enter a syslog port.")]
    [int]$SyslogPort,
    
    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [Parameter(Mandatory=$false,ParameterSetName="FlatFile")]
    [switch]$FlatFile,
    
    [Parameter(Mandatory=$false,ParameterSetName="All")]
    [Parameter(Mandatory=$true,ParameterSetName="FlatFile",HelpMessage="Please enter a storage location.")]
    [string]$FileDir

)


$ExpiryTime = New-TimeSpan -Hours $ExpireTime

# Logging Variables
$EventLogWin = 'Security'
$EventLogName = "Kerb-Canary"

#Syslog Header Values
$CEFVendor = "CEF Canary"
$CEFProduct = $EventLogName
$CEFVersion = "1.0"
$CEFDvcID = #Device Event ID (think vendor specific eventID IE: Security:540)
$CEFName = #Breif Event Name (User Account Changed)
$CEFSeverity = #CEF Serverity 1~10

#Table of EventLog IDs
$EventIDArray = @(
      New-Object PSObject -Property @{EventID = "1000"; EventType = "Info"; EventPri = "1"; EventMsg = "$EventLogName started."}
      New-Object PSObject -Property @{EventID = "1001"; EventType = "Info"; EventPri = "1"; EventMsg = "$EventLogName log created."}
      New-Object PSObject -Property @{EventID = "1002"; EventType = "Info"; EventPri = "1"; EventMsg = "$EventLogName finished."}
      New-Object PSObject -Property @{EventID = "1003"; EventType = "Info"; EventPri = "1"; EventMsg = "$EventLogName couldn't find session information."}
      New-Object PSObject -Property @{EventID = "1004"; EventType = "Info"; EventPri = "1"; EventMsg = "$EventLogName found session information."}
      New-Object PSObject -Property @{EventID = "1005"; EventType = "Info"; EventPri = "1"; EventMsg = "$EventLogName found a normal object."}
      New-Object PSObject -Property @{EventID = "1006"; EventType = "Info"; EventPri = "1"; EventMsg = "TBD"}

      New-Object PSObject -Property @{EventID = "2001"; EventType = "Error"; EventPri = "3"; EventMsg = "$EventLogName encountered an event log permissions error."}
      New-Object PSObject -Property @{EventID = "2002"; EventType = "Error"; EventPri = "3"; EventMsg = "$EventLogName encountered a Klist operational error."}
      New-Object PSObject -Property @{EventID = "2003"; EventType = "Error"; EventPri = "3"; EventMsg = "$EventLogName encountered a get sessions error."}
      New-Object PSObject -Property @{EventID = "2004"; EventType = "Error"; EventPri = "3"; EventMsg = "$EventLogName encountered a syslog server connection error."}
      New-Object PSObject -Property @{EventID = "2005"; EventType = "Error"; EventPri = "3"; EventMsg = "$EventLogName encountered a flatfile output error."}
      New-Object PSObject -Property @{EventID = "2006"; EventType = "Error"; EventPri = "3"; EventMsg = "TBD"}

      New-Object PSObject -Property @{EventID = "3001"; EventType = "Warning"; EventPri = "5"; EventMsg = "$EventLogName found weak encryption object."}
      New-Object PSObject -Property @{EventID = "3002"; EventType = "Warning"; EventPri = "5"; EventMsg = "$EventLogName found generic suspect object."}
      New-Object PSObject -Property @{EventID = "3003"; EventType = "Warning"; EventPri = "5"; EventMsg = "TBD"}

      New-Object PSObject -Property @{EventID = "4001"; EventType = "Alert"; EventPri = "7"; EventMsg = "$EventLogName found abnormal TTL object."}
      New-Object PSObject -Property @{EventID = "4002"; EventType = "Alert"; EventPri = "7"; EventMsg = "TBD"}

      New-Object PSObject -Property @{EventID = "5001"; EventType = "Critical"; EventPri = "9"; EventMsg = "$EventLogName purged a logon session."}
      New-Object PSObject -Property @{EventID = "5002"; EventType = "Critical"; EventPri = "9"; EventMsg = "TBD"}
    )


<# #Debug lines
$ExpiryTime 
$ReportType
$SyslogServer.Value
$SyslogPort.Value
$ResponseType
Pause
#>

#Set Session and bad session arrays
$Global:BadTickets = @()
$Global:LoggingArray = @()

Function MainTicket_Check{
#Convert WMI session IDs to Klist logon format
$LogonSessions = Get-WmiObject -Class Win32_LogonSession
    Foreach($Session in $LogonSessions){
    $Session.LogonID = "0x"+[Convert]::ToString($Session.LogonID, 16)

    }


Foreach($Session in $LogonSessions){
    #$SessionResults = "" | Select LogonID,Has_TGT_Ticket,Has_TGS_Ticket,Clean    
    $SessionResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
    $SessionResults.ClientName = $env:computerName.ToUpper()
    $SessionResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
    $SessionResults.LogonID = $Session.LogonId
    $SessionResults.'Server-Target' = "*"
    $SessionResults.'Server-TargetDomain' = "*"
    $SessionResults.StartTime = ""
    $SessionResults.EndTime = Get-Date -Format g
    $SessionResults.TicketEncrypt = "*"


    #TGT Test Section
    $TGT_Ticket = klist.exe tgt -li $Session.LogonId 
    $SessionResults.TicketType = "TGT"

    If ($TGT_Ticket -match "LsaCallAuthenticationPackage"){
        $SessionResults.TicketType = "TGT"
        $SessionResults.EventID ="1003"
              
        Write-Host "Empty (TGT) objects for: ($($Session.LogonId))" -ForegroundColor Yellow
        $Global:LoggingArray += $SessionResults        
    }
    ElseIf($TGT_Ticket -match "Cached Tickets: \(0\)"){
        $SessionResults.TicketType = "TGT"
        $SessionResults.EventID ="1003"        
        
        Write-Host "Empty (TGT) objects for: ($($Session.LogonId))" -ForegroundColor Yellow
        $Global:LoggingArray += $SessionResults
    }
    ElseIf($TGT_Ticket -match "Operation Failed"){
        $SessionResults.TicketType = "TGT"
        $SessionResults.EventID ="2002"
        
        Write-Host "Klist (TGT) operation failure." -ForegroundColor red
        $Global:LoggingArray += $SessionResults
    }
    Else{ 
        $SessionResults.TicketType = "TGT"
        $SessionResults.EventID ="1004"

        Write-Host "Found (TGT) objects for: ($($Session.LogonId))" -ForegroundColor Green
        $Global:LoggingArray += $SessionResults

         #$TGT_TicketParsed = $TGT_Ticket | ConvertFrom-String -TemplateContent $KTGTParse # Convert from string buggy
         <# $TGT_TicketParsed | Out-GridView # Debug #>

        $TGT_TicketParsed = @()
        for ($i = 1; $i -le $TGT_Ticket.Length; $i++){
        
        $TGT_TicketParser = "" | Select ServiceName,TargetNameSPN,ClientName,ClientDomain,TargetDomain,AltDomain,TicketFlags,TicketFlagsEnum,EncrypType,EncrypTypeEnum,KeyLength,KeyLengthRaw,StartTime,EndTime,RenewTime,TimeSkew,TicketSize

            If($TGT_Ticket[$i] -match "ServiceName\s*\:\s*"){
                If($TGT_Ticket[$i] -match "ServiceName\s*\:\s*"){$ServiceLine = $TGT_Ticket[$i] -split, "ServiceName\s*\:\s*"; 
                $TGT_TicketParser.ServiceName = $ServiceLine[1].ToUpper() ;            
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "TargetName \(SPN\)\s*\:\s*"){$TargetLine = $TGT_Ticket[$i] -split, "TargetName \(SPN\)\s*\:\s*";
                $TGT_TicketParser.TargetNameSPN = $TargetLine[1].ToUpper() ;            
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "ClientName\s*\:\s*"){$ClientLine = $TGT_Ticket[$i] -split, "ClientName\s*\:\s*";
                $TGT_TicketParser.ClientName = $ClientLine[1].ToUpper() ;            
                $i = $i + 1}
                                            
                If($TGT_Ticket[$i] -match "DomainName\s*\:\s*"){$ClientDLine = $TGT_Ticket[$i] -split, "DomainName\s*\:\s*";
                $TGT_TicketParser.ClientDomain = $ClientDLine[1].ToUpper() ;            
                $i = $i + 1}
                            
                If($TGT_Ticket[$i] -match "TargetDomainName\s*\:\s*"){$TargetDLine = $TGT_Ticket[$i] -split, "TargetDomainName\s*\:\s*";
                $TGT_TicketParser.TargetDomain = $TargetDLine[1].ToUpper() ;            
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "AltTargetDomainName\s*\:\s*"){$AltDLine = $TGT_Ticket[$i] -split, "AltTargetDomainName\s*\:\s*";
                $TGT_TicketParser.AltDomain = $AltDLine[1].ToUpper() ;            
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "Ticket Flags\s*\:\s*"){$TktFlgLine = $TGT_Ticket[$i] -split, "Ticket Flags\s*\:\s*"; $FlgSplit = $TktFlgLine[1] -split, " -> "; 
                $TGT_TicketParser.TicketFlags = $($FlgSplit[0].ToUpper())
                $TGT_TicketParser.TicketFlagsEnum = $($FlgSplit[1].ToUpper());
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "Session Key\s*\:\s*KeyType\s*"){$SessFlgLine = $TGT_Ticket[$i] -split, "Session Key\s*\:\s*KeyType\s*"; $SFlgSplit = $SessFlgLine[1] -split, " - "; 
                $TGT_TicketParser.EncrypType = $($SFlgSplit[0].ToUpper())
                $TGT_TicketParser.EncrypTypeEnum = $($SFlgSplit[1].ToUpper());
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "\s*\:\s*KeyLength\s*"){$KeyFlgLine = $TGT_Ticket[$i] -split, "\s*KeyLength\s*"; $KFlgSplit = $KeyFlgLine[1] -split, " - "; 
                $TGT_TicketParser.KeyLength = $($KFlgSplit[0].ToUpper())
                $TGT_TicketParser.KeyLengthRaw = $($KFlgSplit[1].ToUpper());
                $i = $i + 1}

                If($TGT_Ticket[$i] -match "StartTime\s*\:\s*"){$StartTLine = $TGT_Ticket[$i] -split, "StartTime\s*\:\s*";
                $StartT = $StartTLine[1] -split, "\s*\(" ;
                $TGT_TicketParser.StartTime = $([datetime]$StartT[0]) ; 
                $i = $i + 1}
                                                                            
                If($TGT_Ticket[$i] -match "EndTime\s*\:\s*"){$EndTLine = $TGT_Ticket[$i] -split, "EndTime\s*\:\s*";
                $EndT = $EndTLine[1] -split, "\s*\(" ; 
                $TGT_TicketParser.EndTime =$([datetime]$EndT[0]);
                $i = $i + 1}
            
                If($TGT_Ticket[$i] -match "RenewUntil\s*\:\s*"){$RenewTLine = $TGT_Ticket[$i] -split, "RenewUntil\s*\:\s*";
                $RenewT = $RenewTLine[1] -split, "\s*\(" ;
                $TGT_TicketParser.RenewTime = $([datetime]$RenewT[0]);
                $i = $i + 1}
            
                If($TGT_Ticket[$i] -match "TimeSkew\s*\:\s*"){$SkewLine = $TGT_Ticket[$i] -split, "TimeSkew\s*\:\s*"; 
                $TGT_TicketParser.TimeSkew = "$([string]$SkewLine[1].ToUpper())";
                $i = $i + 1}
            
                If($TGT_Ticket[$i] -match "EncodedTicket\s*\:\s*"){$SkewLine = $TGT_Ticket[$i] -split, "EncodedTicket\s*\:\s*"; 
                $TGT_TicketParser.TicketSize = "$([string]$SkewLine[1].ToUpper())";
                $i = $i + 1}

                $TGT_TicketParsed += $TGT_TicketParser

            Continue
            }
        }

         Foreach($Ticket in $TGT_TicketParsed){
            $TicketResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID

            #Do Golden TGT Check here
            $TicketTimeDiff = $Ticket.EndTime - $Ticket.StartTime
            <# $TicketTimeDiff # Debug #>
            
            If($TicketTimeDiff -gt $ExpiryTime){               
                Write-Host "Suspect (TGT) object for: ($($Session.LogonId)) - Abnormal TTL" -ForegroundColor Red
               
                $TicketResults.LogonID = $Session.LogonId
                $TicketResults.TicketType = "TGT"
                $TicketResults.ClientName = $Ticket.ClientName
                $TicketResults.ClientDomain = $Ticket.ClientDomain
                $TicketResults.'Server-Target' = $Ticket.TargetNameSPN
                $TicketResults.'Server-TargetDomain' = $Ticket.TargetDomain
                $TicketResults.StartTime = $Ticket.StartTime
                $TicketResults.EndTime = $Ticket.EndTime
                $TicketResults.TicketEncrypt = $Ticket.EncrypTypeEnum
                $TicketResults.EventID ="4001"

                $Global:LoggingArray += $TicketResults
                #break
            }
            ElseIf($Ticket.EncrypTypeEnum -match "RC4"){
                Write-Host "Suspect (TGT) object for: ($($Session.LogonId)) - Weak Encryption Cipher" -ForegroundColor Red
                                
                $TicketResults.LogonID = $Session.LogonId
                $TicketResults.TicketType = "TGT"
                $TicketResults.ClientName = $Ticket.ClientName
                $TicketResults.ClientDomain = $Ticket.ClientDomain
                $TicketResults.'Server-Target' = $Ticket.TargetNameSPN
                $TicketResults.'Server-TargetDomain' = $Ticket.TargetDomain
                $TicketResults.StartTime = $Ticket.StartTime
                $TicketResults.EndTime = $Ticket.EndTime
                $TicketResults.TicketEncrypt = $Ticket.EncrypTypeEnum
                $TicketResults.EventID ="3001"
                
                $Global:LoggingArray += $TicketResults
            }
            Else{
                
                Write-Host "Clean (TGT) object for: ($($Session.LogonId))" -ForegroundColor Green
                $TicketResults.LogonID = $Session.LogonId
                $TicketResults.TicketType = "TGT"
                $TicketResults.ClientName = $Ticket.ClientName
                $TicketResults.ClientDomain = $Ticket.ClientDomain
                $TicketResults.'Server-Target' = $Ticket.TargetNameSPN
                $TicketResults.'Server-TargetDomain' = $Ticket.TargetDomain
                $TicketResults.StartTime = $Ticket.StartTime
                $TicketResults.EndTime = $Ticket.EndTime
                $TicketResults.TicketEncrypt = $Ticket.EncrypTypeEnum
                $TicketResults.EventID = "1005"
                
                $Global:LoggingArray += $TicketResults         
            }
            
         }
    }


    $SessionResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
    $SessionResults.ClientName = $env:computerName.ToUpper()
    $SessionResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
    $SessionResults.LogonID = $Session.LogonId
    $SessionResults.'Server-Target' = "*"
    $SessionResults.'Server-TargetDomain' = "*"
    $SessionResults.StartTime = ""
    $SessionResults.EndTime = Get-Date -Format g
    $SessionResults.TicketEncrypt = "*"

    #TGS Test Section
    $TGS_Ticket = klist.exe tickets -li $Session.LogonId
     
    If ($TGS_Ticket -match "LsaCallAuthenticationPackage"){
        $SessionResults.TicketType = "TGS"
        $SessionResults.EventID ="1003"
        
        Write-Host "Empty (TGS) objects for: ($($Session.LogonId))" -ForegroundColor Yellow
        $Global:LoggingArray += $SessionResults
    }
    ElseIf($TGS_Ticket -match "Cached Tickets: \(0\)"){
        $SessionResults.TicketType = "TGS"
        $SessionResults.EventID ="1003"
        
        Write-Host "Empty (TGS) objects for: ($($Session.LogonId))" -ForegroundColor Yellow
        $Global:LoggingArray += $SessionResults
    }
    ElseIf($TGS_Ticket -match "Operation Failed"){
        $SessionResults.TicketType = "TGS"
        $SessionResults.EventID ="2002"
        
        Write-Host "Klist (TGS) operation failure." -ForegroundColor red
        $Global:LoggingArray += $SessionResults
    }
    Else{ 
        $SessionResults.TicketType = "TGS"
        $SessionResults.EventID ="1004"
        
        Write-Host "Found (TGS) objects for: ($($Session.LogonId))" -ForegroundColor Green
        $Global:LoggingArray += $SessionResults

        #$TGS_TicketParsed = $TGS_Ticket | ConvertFrom-String -TemplateContent $KTGSParse # Convert from string buggy
        <# $TGS_TicketParsed | Out-GridView # Debug #>

        $TGS_TicketParsed = @()
        for ($i = 1; $i -le $TGS_Ticket.Length; $i++){
        
        $TGS_TicketParser = "" | Select ClientName, ClientDomain, ServerName, ServerDomain, EncrypTypeEnum,TicketFlags,TicketFlagsEnum,StartTime,EndTime,RenewTime,SessionKeyType

            If($TGS_Ticket[$i] -match "#\d>"){
                If($TGS_Ticket[$i] -match "Client:\s*"){$ClientLine = $TGS_Ticket[$i] -split, "Client:\s*"; $Client = $ClientLine[1] -split, " @ " ; 
                $TGS_TicketParser.ClientName = $($Client[0].ToUpper()) ;
                $TGS_TicketParser.ClientDomain = $($Client[1].ToUpper()) ; 
                $i = $i + 1}

                If($TGS_Ticket[$i] -match "Server:\s*"){$ServerLine = $TGS_Ticket[$i] -split, "Server:\s*"; $Server = $ServerLine[1] -split, " @ ";  
                $TGS_TicketParser.ServerName = $($Server[0].ToUpper()) ;
                $TGS_TicketParser.ServerDomain = $($Server[1].ToUpper()); 
                $i = $i + 1}

                If($TGS_Ticket[$i] -match "KerbTicket Encryption Type:\s*"){$KerbTktLine = $TGS_Ticket[$i] -split, "KerbTicket Encryption Type:\s*";
                $TGS_TicketParser.EncrypTypeEnum = $($KerbTktLine[1].ToUpper())
                $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "Ticket Flags\s*"){$TktFlgLine = $TGS_Ticket[$i] -split, "Ticket Flags\s*"; $FlgSplit = $TktFlgLine[1] -split, " -> "; 
                $TGS_TicketParser.TicketFlags = $($FlgSplit[0])
                $TGS_TicketParser.TicketFlagsEnum = $($FlgSplit[1].ToUpper());
                $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "Start Time:\s*"){$StartTLine = $TGS_Ticket[$i] -split, "Start Time:\s*"; $StartT = $StartTLine[1] -split, "\s\(" ; 
                $TGS_TicketParser.StartTime = $([datetime]$StartT[0]) ; 
                $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "End Time:\s*"){$EndTLine = $TGS_Ticket[$i] -split, "End Time:\s*"; $EndT = $EndTLine[1] -split, "\s\(" ; 
                $TGS_TicketParser.EndTime =$([datetime]$EndT[0])
                ; $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "Renew Time:\s*"){$RenewTLine = $TGS_Ticket[$i] -split, "Renew Time:\s*";
                $RenewT = $RenewTLine[1] -split, "\s\(" ;
                $TGS_TicketParser.RenewTime = $([datetime]$RenewT[0]);
                $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "Session Key Type:\s*"){$SessTypeLine = $TGS_Ticket[$i] -split, "Session Key Type:\s*"; 
                $TGS_TicketParser.SessionKeyType = "$([string]$SessTypeLine[1].ToUpper())";
                $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "Cache Flags:\s*"){$CachFlgLine = $TGS_Ticket[$i] -split, "Cache Flags:\s*"; $CacheSplit = $CachFlgLine[1].ToUpper() -split, " -> "; 
                #Write-Host "$($CacheSplit[0]) , $($CacheSplit[1])";
                $i = $i + 1}
            
                If($TGS_Ticket[$i] -match "Kdc Called:\s*"){$kdcLine = $TGS_Ticket[$i].ToUpper() -split, "Kdc Called:\s*"; 
                #Write-Host "$($KdcLine[1])";
                $i = $i + 1}
                $TGS_TicketParsed += $TGS_TicketParser
            Continue
            }
        }

        Foreach($Ticket in $TGS_TicketParsed){
            $TicketResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
            #Do Golden TGS Checks here
            $TicketTimeDiff = $Ticket.EndTime - $Ticket.StartTime
            <# $TicketTimeDiff # Debug #>

            If($TicketTimeDiff -gt $ExpiryTime){
                Write-Host "Suspect (TGS) object for: ($($Session.LogonId)) - Abnormal TTL" -ForegroundColor Red
                               
                $TicketResults.LogonID = $Session.LogonId
                $TicketResults.TicketType = "TGS"
                $TicketResults.ClientName = $Ticket.ClientName
                $TicketResults.ClientDomain = $Ticket.ClientDomain
                $TicketResults.'Server-Target' = $Ticket.ServerName
                $TicketResults.'Server-TargetDomain' = $Ticket.ServerDomain
                $TicketResults.StartTime = $Ticket.StartTime
                $TicketResults.EndTime = $Ticket.EndTime
                $TicketResults.TicketEncrypt = $Ticket.EncrypTypeEnum 
                $TicketResults.EventID ="4001"
                                               
                $Global:LoggingArray += $TicketResults
                #break    
            }
            ElseIf(($Ticket.EncrypTypeEnum -match "RC4")){
                Write-Host "Suspect (TGS) object for: ($($Session.LogonId)) - Weak Encryption Cipher" -ForegroundColor Red
                                
                $TicketResults.LogonID = $Session.LogonId
                $TicketResults.TicketType = "TGS"
                $TicketResults.ClientName = $Ticket.ClientName
                $TicketResults.ClientDomain = $Ticket.ClientDomain
                $TicketResults.'Server-Target' = $Ticket.ServerName
                $TicketResults.'Server-TargetDomain' = $Ticket.ServerDomain
                $TicketResults.StartTime = $Ticket.StartTime
                $TicketResults.EndTime = $Ticket.EndTime
                $TicketResults.TicketEncrypt = $Ticket.EncrypTypeEnum
                $TicketResults.EventID ="3001"
                                
                $Global:LoggingArray += $TicketResults
                #break    
            }
            Else{
                Write-Host "Clean (TGS) object for: ($($Session.LogonId))" -ForegroundColor Green
                $TicketResults.LogonID = $Session.LogonId
                $TicketResults.TicketType = "TGS"
                $TicketResults.ClientName = $Ticket.ClientName
                $TicketResults.ClientDomain = $Ticket.ClientDomain
                $TicketResults.'Server-Target' = $Ticket.ServerName
                $TicketResults.'Server-TargetDomain' = $Ticket.ServerDomain
                $TicketResults.StartTime = $Ticket.StartTime
                $TicketResults.EndTime = $Ticket.EndTime
                $TicketResults.TicketEncrypt = $Ticket.EncrypTypeEnum
                $TicketResults.EventID = "1005"
                
                $Global:LoggingArray += $TicketResults
            }

        }
    }
      
    
}
}

Function EventLog_Check{
IF([System.Diagnostics.EventLog]::SourceExists($EventLogName)){
    Write-Host $EventLogName "log source already exists." -ForegroundColor Green
        Try{
        Write-EventLog -LogName $EventLogWin -Source $EventLogName -Category 0 -EventId "1001" -Message "$EventLogName was started." -ErrorAction Stop
        }
        Catch {
        Write-Host "Event Log couldn't be written, check permissions or reboot device." -ForegroundColor Red
        $WinResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
        $WinResults.LogonID = "Error"
        $WinResults.TicketType = "ERR"
        $WinResults.ClientName = $env:computerName.ToUpper()
        $WinResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
        $WinResults.'Server-Target' = "*"
        $WinResults.'Server-TargetDomain' = "*"
        $WinResults.StartTime = ""
        $WinResults.EndTime = Get-Date -Format g
        $WinResults.TicketEncrypt = "*"
        $WinResults.EventID = "2001"
                
        $Global:LoggingArray += $WinResults
        Throw
        }
    }
    Else
    {
    Write-Host $EventLogName "log source doesn't exist...Creating." -ForegroundColor Yellow
    New-EventLog -LogName $EventLogWin -Source $EventLogName
        IF([System.Diagnostics.EventLog]::SourceExists($EventLogName)){
        Write-Host $EventLogName "log source created." -ForegroundColor Green
            Try{Write-EventLog -LogName $EventLogWin -Source $EventLogName -Category 0 -EventId "1000" -Message "$EventLogName log created." -ErrorAction Stop
            
            }
            Catch{
            Write-Host "Event Log couldn't be written, check permissions or reboot device." -ForegroundColor Red
            $WinResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
            $WinResults.LogonID = "Error"
            $WinResults.TicketType = "ERR"
            $WinResults.ClientName = $env:computerName.ToUpper()
            $WinResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
            $WinResults.'Server-Target' = "*"
            $WinResults.'Server-TargetDomain' = "*"
            $WinResults.StartTime = ""
            $WinResults.EndTime = Get-Date -Format g
            $WinResults.TicketEncrypt = "*"
            $WinResults.EventID = "2001"
                
            $Global:LoggingArray += $WinResults
            Throw
            }
        }
        Else{Throw}
    }
}

Function CEFSyslogSender ()
{
<#
.DESCRIPTION
Basic usage:
$Obj = ./CEFSyslogSender 192.168.2.4
$Obj.Send("string message1")
$Obj.Send("string message2")
$Obj.Send($message)
    
EXAMPLE: $Syslog.Send("Dummy","Product","1234","Dummy EventID","Dummy EventName","10","msg=Test Message 1318")

<14>Jun 23 13:18:40 : CEF:0|Dummy|Product|1234|Dummy EventID|Dummy EventName|10|msg=Test Message 1318
#> 


Param
(
[String]$Destination = $(throw "ERROR: SYSLOG Host Required..."),
[Int32]$Port = 514
)


# Use Test-Connection function to determine IP address from hostname and redefine "Destination" variable
Try{
    $Con = Test-Connection -ComputerName $Destination -Count 1 -ErrorAction Stop
    If($con.IPV4Address){
        $Destination = $con.IPV4Address.IPAddressToString
    }
    Else{
        $Destination = $con.Address
    }
}

Catch{
"ERROR: Valid SYSLOG Host Required..."
THrow
}

$ObjSyslogSender = New-Object PsObject
$ObjSyslogSender.PsObject.TypeNames.Insert(0, "SyslogSender")

# Initialize the udp 'connection'
$ObjSyslogSender | Add-Member -MemberType NoteProperty -Name UDPClient -Value $(New-Object System.Net.Sockets.UdpClient)
$ObjSyslogSender.UDPClient.Connect($Destination, $Port)

# Add the Send method:
$ObjSyslogSender | Add-Member -MemberType ScriptMethod -Name Send -Value {

Param
(
[String]$CEFVendor = "Generic Vendor",
[String]$CEFProduct = "Generic Product",
[String]$CEFVersion = "1.2.3.4",
[String]$CEFDvcID = "Device Event ID",
[String]$CEFName = "Generic Event Name",
[String]$CEFSeverity = "1",
[String]$Data = $(throw "Error SyslogSender: No data to send!")
)

[String]$CEFHeader = "CEF:0"
[String]$Timestamp = $(get-date -UFormat %b" "%d" "%T)
[String]$Source = "CEF Syslog Sender"
[String]$Severity = "info"
[String]$Facility = "user"
[String]$Hostname = $env:COMPUTERNAME



#Checking for blank input fields, insert defaults as needed per use-case. These will substitute any blank fields when the function is called with "".

IF([string]::IsNullOrWhiteSpace($CEFHeader)){
$CEFHeader = "CEF:0"
}

IF([string]::IsNullOrWhiteSpace($CEFVendor)){
$CEFVendor = "Generic Vendor"
}

IF([string]::IsNullOrWhiteSpace($CEFProduct)){
$CEFProduct = "Generic Product"
}

IF([string]::IsNullOrWhiteSpace($CEFVersion)){
$CEFVersion = "1.2.3.4"
}

IF([string]::IsNullOrWhiteSpace($CEFDvcID)){
$CEFDvcID = "Device Event ID"
}

IF([string]::IsNullOrWhiteSpace($CEFName)){
$CEFName = "Generic Event Name"
}

IF([string]::IsNullOrWhiteSpace($CEFSeverity))
{
$CEFSeverity = "1"
}

# Set basic syslog priority code to "8" (Emergency), this is overriden by CEF fields ($CEFSeverity).
$PRI = 8

#Build message content from inputs and CEF data/strings.
$Message = "<$PRI>$Timestamp : $CEFHeader|$CEFVendor|$CEFProduct|$CEFVersion|$CEFDvcID|$CEFName|$CEFSeverity|$Data"

#Format the data, recommended is a maximum length of 1kb
$Message = $([System.Text.Encoding]::ASCII).GetBytes($message)

#write-host $Message
if ($Message.Length -gt 4096)
{
$Message = $Message.Substring(0, 4096)
}
# Send the message

$this.UDPClient.Send($Message, $Message.Length) | Out-Null

}
$ObjSyslogSender
}

Function Update_EventID{
$Global:LoggingArray | Add-Member -MemberType NoteProperty "EventType" -Value "" -Force
$Global:LoggingArray | Add-Member -MemberType NoteProperty "EventPri" -Value "" -Force
$Global:LoggingArray | Add-Member -MemberType NoteProperty "EventMsg" -Value "" -Force
 

Foreach($Log in $Global:LoggingArray){
        $EventIndex = [array]::indexof($EventIDArray.EventID,$Log.EventID)
        If($EventIndex){
        
        $Log.EventType = $EventIDArray[$EventIndex].EventType
        $Log.EventPri = $EventIDArray[$EventIndex].EventPri
        $Log.EventMsg = $EventIDArray[$EventIndex].EventMsg
        
        }    
}

If($ReportLevel -eq "Info"){
}
ElseIf($ReportLevel -eq "Error"){
$Global:LoggingArray = $Global:LoggingArray | Where { $_.EventType -ne "Info"}
}
ElseIf($ReportLevel -eq "Warning"){
$Global:LoggingArray = $Global:LoggingArray | Where { $_.EventType -ne "Info" -and $_.EventType -ne "Error"}
}
ElseIf($ReportLevel -eq "Alert"){
$Global:LoggingArray = $Global:LoggingArray | Where { $_.EventType -ne "Info" -and $_.EventType -ne "Error" -and $_.EventType -ne "Warning"}
}
}

Function SessionShreder{
    $ShreddedSessions = @()
    Foreach($Log in $Global:LoggingArray){
        If(($ResponseLevel -eq "Alert" -and $Log.EventType -eq "Alert")-and $ShreddedSessions -notcontains $Log.LogonID){
            $ShredResults= "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
            $ShredResults.LogonID = $Log.LogonID
            $ShredResults.TicketType = $Log.TicketType
            $ShredResults.ClientName = $Log.ClientName
            $ShredResults.ClientDomain = $Log.ClientDomain
            $ShredResults.'Server-Target' = $Log.'Server-Target'
            $ShredResults.'Server-TargetDomain' = $Log.'Server-TargetDomain'
            $ShredResults.StartTime = ""
            $ShredResults.EndTime = Get-Date -Format g
            $ShredResults.TicketEncrypt = $Log.TicketEncrypt
            $ShredResults.EventID = "5001"
        
            Write-Host "Warning: Session $($Log.LogonID) was purged due a $ResponseLevel or above level event." -ForegroundColor Red    
            $ShredIt = klist.exe -li $Log.LogonId purge 

            $Global:LoggingArray += $ShredResults
            $ShreddedSessions += $Log.LogonID
        

        }
        ElseIf(($ResponseLevel -eq "Warning" -and ($Log.EventType -eq "Alert" -or $Log.EventType -eq "Warning")) -and $ShreddedSessions -notcontains $Log.LogonID){
            $ShredResults= "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
            $ShredResults.LogonID = $Log.LogonID
            $ShredResults.TicketType = $Log.TicketType
            $ShredResults.ClientName = $Log.ClientName
            $ShredResults.ClientDomain = $Log.ClientDomain
            $ShredResults.'Server-Target' = $Log.'Server-Target'
            $ShredResults.'Server-TargetDomain' = $Log.'Server-TargetDomain'
            $ShredResults.StartTime = ""
            $ShredResults.EndTime = Get-Date -Format g
            $ShredResults.TicketEncrypt = $Log.TicketEncrypt
            $ShredResults.EventID = "5001"
        
            Write-Host "Warning: Session $($Log.LogonID) was purged due a $ResponseLevel or above level event." -ForegroundColor Red    
            $ShredIt = klist.exe -li $Log.LogonId purge

            $Global:LoggingArray += $ShredResults
            $ShreddedSessions += $Log.LogonID       
        }    
    }

$ShreddedSessions
}

MainTicket_Check


If($ResponseLevel -ne "None"){
    Update_EventID
    SessionShreder
}

# Send results to syslog server/SIEM
If($Syslog){
    Update_EventID
    
    Try{
        $SyslogTarget = CEFSyslogSender -Destination $SyslogServer -Port 510 $SyslogPort
        
        Foreach($Log in $Global:LoggingArray){
                       
            $SyslogTarget.Send("$CEFVendor","$CEFProduct","$CEFVersion","$($Log.EventID)","$($Log.EventMsg)","$($Log.EventPri)","msg=$($Log.EventMsg) reason=$($Log.EventType) shost=$env:computerName cs1Label=TicketType cs1=$($Log.TicketType) cs2Label=TicketEncypt cs2=$($Log.TicketEncrypt) cs3Label=ClientName cs3=$($Log.ClientName) cs4Label=ClientDomain cs4=$($Log.ClientDomain) cs5Label=Server-Target cs5=$($Log.'Server-Target') cs6Label=Server-TargetDomain cs6=$($Log.'Server-TargetDomain') deviceCustomDate1Label=StartTime deviceCustomDate1=$($Log.StartTime| Get-Date -Format "MMM dd yyyy HH:mm:ss zzz" -ErrorAction SilentlyContinue ) deviceCustomDate2Label=EndTime deviceCustomDate2=$($Log.EndTime|Get-Date -Format "MMM dd yyyy HH:mm:ss zzz"-ErrorAction SilentlyContinue)")
            }
        }
    Catch{
        $CEFResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
        $CEFResults.LogonID = "Error"
        $CEFResults.TicketType = "*"
        $CEFResults.ClientName = $env:computerName.ToUpper()
        $CEFResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
        $CEFResults.'Server-Target' = "*"
        $CEFResults.'Server-TargetDomain' = "*"
        $CEFResults.StartTime = ""
        $CEFResults.EndTime = Get-Date -Format g
        $CEFResults.TicketEncrypt = "*"
        $CEFResults.EventID = "2004"
        $Global:LoggingArray += $CEFResults   

        Write-Host "Syslog output error, dumping output to screen." -ForegroundColor Red        
        $LogError = $true
        } 
}

# Send results to windows event log.
If($EventLog){
    Update_EventID
    Try{
        EventLog_Check
        Foreach($BadTicket in $Global:BadTickets){
            Try{
                Write-Host "Wrote to the Windows Event log - $EventLogWin."
            }
            Catch {
                $WinResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
                $WinResults.LogonID = "Error"
                $WinResults.TicketType = "*"
                $WinResults.ClientName = $env:computerName.ToUpper()
                $WinResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
                $WinResults.'Server-Target' = "*"
                $WinResults.'Server-TargetDomain' = "*"
                $WinResults.StartTime = ""
                $WinResults.EndTime = Get-Date -Format g
                $WinResults.TicketEncrypt = "*"
                $WinResults.EventID = "2001"
                $Global:LoggingArray += $WinResults
            }
        }
    }
    Catch{
        Write-Host "Event Log output error, dumping output to screen." -ForegroundColor Red
        $LogError = $true
    }
}

# Send results to a flat file
If($FlatFile){
    Update_EventID
    Try{
        $CSVOut = $Global:LoggingArray | ConvertTo-Csv -NoTypeInformation  
        New-Item -force -path $FileDir -value $CSVOut -type file -ErrorAction Stop 
    }
    Catch{
        $FileResults = "" | Select LogonID, TicketType, ClientName, ClientDomain, Server-Target, Server-TargetDomain, StartTime, EndTime, TicketEncrypt,EventID
        $FileResults.LogonID = "Error"
        $FileResults.TicketType = "*"
        $FileResults.ClientName = $env:computerName.ToUpper()
        $FileResults.ClientDomain = If($env:USERDOMAIN -eq $env:computerName){"Workgroup"}Else{((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()}
        $FileResults.'Server-Target' = "*"
        $FileResults.'Server-TargetDomain' = "*"
        $FileResults.StartTime = ""
        $FileResults.EndTime = Get-Date -Format g
        $FileResults.TicketEncrypt = "*"
        $FileResults.EventID = "2005"
        $Global:LoggingArray += $FileResults   
        
        Write-Host "Flatfile output error, dumping output to screen." -ForegroundColor Red        
        $LogError = $true
    } 
}

If($LogError){
Update_EventID
$Global:LoggingArray | FT *
}
ElseIf($VerboseUp -and !$LogError){
Update_EventID
$Global:LoggingArray | FT *
}