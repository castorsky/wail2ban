################################################################################
#                        _ _ ____  _
#         __      ____ _(_) |___ \| |__   __ _ _ __
#         \ \ /\ / / _` | | | __) | '_ \ / _` | '_ \
#          \ V  V / (_| | | |/ __/| |_) | (_| | | | |
#           \_/\_/ \__,_|_|_|_____|_.__/ \__,_|_| |_|
#
################################################################################
#
# For help, read the below function.
#
function help {
	"`nwail2ban	 `n"
	"wail2ban is an attempt to recreate fail2ban for windows, hence [w]indows f[ail2ban]."
	" "
	"wail2ban takes configured events known to be audit failures, or similar, checks for "+`
	"IPs in the event message, and given sufficient failures, bans them for a small amount"+`
	"of time."
	" "
	"Settings: "
	" -config		: show the settings that are being used "
	" -jail			: show the currently banned IPs"
	" -jailbreak : bust out all the currently banned IPs"
	" -help			: This message."
	" "
}


$DebugPreference = "continue"

################################################################################
#	Constants

$CHECK_WINDOW = 120	# We check the most recent X seconds of log.				 Default: 120
$CHECK_COUNT	= 5		# Ban after this many failures in search period.		 Default: 5
$MAX_BANDURATION = 7776000 # 3 Months in seconds

################################################################################
#	Files

$wail2banInstall = ""+(split-path -parent $MyInvocation.MyCommand.Definition)+"\"
$logFile			= $wail2banInstall+"wail2ban_log.log"
$ConfigFile			= $wail2banInstall+"wail2ban_config.ini"
$BannedIPLog		= $wail2banInstall+"bannedIPLog.ini"

# Mikrotik initialization section
$mikroModuleName	= "Mikrotik"
$mikroModulePath	= $wail2banInstall+$mikroModuleName+".dll"
$addrListName		= "wail2ban"
$mikroConnection	= $null

################################################################################
# Constructs

$RecordEventLog		 = "Application"		 # Where we store our own event messages
$FirewallRulePrefix = "wail2ban block:" # What we name our Rules
$EventTypes = "Application,Security,System"		#Event logs we allow to be processed

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

# Block list structure: { IP = (address, blockPeriod) }
$BannedIPs = @{}
# Incoming event table structure
$CheckEvents = New-object system.data.datatable("CheckEvents")
$null = $CheckEvents.columns.add("EventLog")
$null = $CheckEvents.columns.add("EventID")
$null = $CheckEvents.columns.add("EventDescription")

$WhiteList = @()
#$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(100,50)

# You can overload the BlockType here for 2003, if you feel like having fun.
$OSVersion = Invoke-Expression "wmic os get Caption /value"
if ($OSVersion -match "2008") { $BLOCK_TYPE = "NETSH" }
if ($OSVersion -match "2012") { $BLOCK_TYPE = "NETSH" }
if ($OSVersion -match "2016") { $BLOCK_TYPE = "NETSH" }

# Grep configuration file
switch -regex -file $ConfigFile {
	# [Header]
	"^\[(.+)\]$" {
		$Header = $matches[1].Trim()
	}
	# 12345=Event
	# INI-format have semicolon sign as comment start
	"^\s*([^;].+?)\s*=\s*(.*)" {
		$Match1 = $matches[1]
		$Match2 = $matches[2]

		if ( $EventTypes -match $Header ) {
			$row = $CheckEvents.NewRow()
			$row.EventLog = $Header
			$row.EventID = $Match1
			$row.EventDescription = $Match2
			$CheckEvents.Rows.Add($row)
		} else {
			switch ($Header) {
				"Whitelist" { $WhiteList += $Match1; }
				"Mikrotik" {
					$BLOCK_TYPE = "MIKROTIK"
					switch ($Match1) {
						"address" { $mikroIP = $Match2 }
						"user" { $mikroUser = $Match2 }
						"password" { $mikroPassword = $Match2 }
						"ssl" { $mikroSSL = $Match2 }
					}
				}
			}

		}
	}

}

# We also want to whitelist this machine's NICs.
# Address field in non-english Windows may have other name
# so search for IPv4 text
$SelfList = @()
foreach ($listing in ((ipconfig | findstr [0-9].\.))) {
	#if ($listing -match "Address" ){ 	$SelfList += $listing.Split()[-1] }
	if ($listing -match "IPv4" ){ 	$SelfList += $listing.Split()[-1] }
}

################################################################################
# Functions

# Register script action in system log
function Register-Event ($text,$task,$result) {
	$event = New-Object System.Diagnostics.EventLog($RecordEventLog)
	$event.Source="wail2ban"
	switch ($task) {
		"ADD"		{ $logeventID = 1000 }
		"REMOVE"	{ $logeventID = 2000 }
	}
	switch ($result) {
		"FAIL"	{ $eventtype = [System.Diagnostics.EventLogEntryType]::Error; $logeventID += 1 }
		default	{ $eventtype = [System.Diagnostics.EventLogEntryType]::Information}
	}
	$event.WriteEntry($text,$eventType,$logeventID)
}

# Write-Log type functions
function Write-LogError		($text) { Write-Log "E" $text }
function Write-LogWarning	($text) { Write-Log "W" $text }
function Write-LogDebug		($text) { Write-Log "D" $text }
function Write-LogAction	($text) { Write-Log "A" $text }

# Write-Log things to file and debug
function Write-Log ($type, $text) {
	$output = ""+(Get-Date -format u).replace("Z","")+" $tag $text"
	if ($type -eq "A") { $output | Out-File $logfile -append}
	switch ($type) {
		"D" { Write-Debug $output}
		"W" { Write-Warning "WARNING: $output"}
		"E" { Write-Error "ERROR: $output"}
		"A" { Write-Debug $output }
	}
}

# Get the current list of wail2ban bans from firewall rules
# Return hashtable "blockList"
function Read-BlockList {
	$blockList = @{}
	switch ($BLOCK_TYPE) {
		"NETSH" {
			$firewall = New-Object -ComObject hnetcfg.fwpolicy2
			$result = $firewall.rules | Where-Object { $_.name -match $FirewallRulePrefix } | Select-Object name, description
			foreach ($string in $result) {
				if ($string.name -match ".*wail2ban.*:\s+(?<IP>.*)") {
					$IP = $matches.IP
					if ($string.description -match ".*Expire\:\s+(?<expire>.*)") {
						$blockList.Add($IP, $matches.expire)
					}
				}
			}
			return $blockList
		}
		"MIKROTIK" {
			$execCmd = 'Send-Mikrotik'
				$execParams = @{
					Connection	= $mikroConnection
					Command		= "/ip/firewall/address-list/print"
					Filters		= "list=wail2ban"
				}
			$result = & $execCmd @execParams
			foreach ($string in $result) {
				if ($string -match "^\.id=(?<ID>.*?)=.*=address=(?<IP>.*?)=.*=comment=Expire: (?<comment>.*)") {
					$blockList.Add($matches.IP, $matches.comment)
				}				
			}
			return $blockList
		}
		Default {
			Write-LogError "Cannot read rules list. Don't have a known Block Type. $BLOCK_TYPE"
		}
	}
}

# Confirm if rule exists for specified IP
function Test-RuleExists ($IP) {
	switch($BLOCK_TYPE) {
		"NETSH" {
			$getRulesExec = 'netsh'
			$getRulesExecArgs = @(
				"advfirewall", "firewall", "show", "rule",
				"name=", "$FirewallRulePrefix $IP"
			)
			$getRulesCmdletArgs = @{}
		}
		"MIKROTIK" {
			$getRulesExec = 'Send-Mikrotik'
			$getRulesExecArgs = @()
			$getRulesCmdletArgs = @{
					Connection 	= $mikroConnection
					Command 	= "/ip/firewall/address-list/print"
					Filters		= "address=$IP"
			}
		}
		Default {
			Write-LogError "Cannot check existance. Don't have a known Block Type. $BLOCK_TYPE"
		}
	}
	if ($getRulesExec) {
		$result = & $getRulesExec @getRulesExecArgs @getRulesCmdletArgs
		if ($result -match ".*wail2ban.*$IP") {
			return $true
		} else {
			return $false
		}
	}
}

# Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function Convert-Netmask ($netmaskValue) {
	$IPAddress =	[UInt32]([Convert]::ToUInt32($(("1" * $netmaskValue).PadRight(32, "0")), 2))
	$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
		$Remainder = $IPAddress % [Math]::Pow(256, $i)
		($IPAddress - $Remainder) / [Math]::Pow(256, $i)
		$IPAddress = $Remainder
	} )

	Return [String]::Join('.', $DottedIP)
}

# Check if IP is whitelisted
function Search-Whitelist ($IP) {
	foreach ($whitelistEntry in $Whitelist) {
		# Check single address
		if ($IP -eq $whitelistEntry) {
			$Whitelisted = "Uniquely listed."
			break
		}
		# Check subnet specified by mask
		if ($whitelistEntry.contains("/")) {
			$netmask = Convert-Netmask($whitelistEntry.Split("/")[1])
			$subnet = $whitelistEntry.Split("/")[0]
			if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$netmask).Address ) 	-eq`
				(([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$netmask).Address ))
			{
				$Whitelisted = "Contained in subnet $whitelistEntry"; break;
			}
		}
	}
	return $Whitelisted
}

# Read in the saved file of settings. Only called on script start, such as after reboot
function Read-BlockPeriodLog {
	if (Test-Path $BannedIPLog) {
		Get-Content $BannedIPLog | ForEach-Object{
		if (!$BannedIPs.ContainsKey($_.split(" ")[0])) {
			$BannedIPs.Add($_.split(" ")[0], $_.split(" ")[1]) }
		}
		Write-LogDebug "$BannedIPLog ban counts loaded"
	} else {
		Write-LogDebug "No IPs to collect from BannedIPLog"
	}
}

# Get the block time for an IP from list of blocked IPs, in seconds
function Get-BlockPeriod ($IP) {
	if ($BannedIPs.ContainsKey($IP)) {
		# blockGrade is formal level of blocking
		# after will be converted to seconds
		[int]$blockGrade = $BannedIPs.Get_Item($IP)
	} else {
		$blockGrade = 0
		$BannedIPs.Add($IP, $blockGrade)
	}
	$blockGrade++
	$BannedIPs.Set_Item($IP, $blockGrade)

	# Set block period as power of 5
	$blockPeriod =	[math]::min([math]::pow(5,$blockGrade)*60, $MAX_BANDURATION)
	Write-LogDebug "IP $IP has the new setting of $blockGrade, being $blockPeriod seconds"
	if (Test-Path $BannedIPLog) {
		Clear-Content $BannedIPLog
	} else {
		New-Item $BannedIPLog -type file
	}
	$BannedIPs.keys	| ForEach-Object{ "$_ "+$BannedIPs.Get_Item($_) | Out-File $BannedIPLog -Append }
	return $blockPeriod
	}

# Block the IP (with checking)
function Block-Address ($IP, $expireDate) {
	# Is address whitelisted?
	$result = Search-Whitelist ($IP)
	if ($result) {
		# then write message and do nothing
		Write-LogWarning "$IP is whitelisted, except from banning. Why? $result "
	} else {
		if (!$expireDate) {
			# If expireDate not specified get it from BannedIPLog
			$blockPeriod = Get-BlockPeriod($IP)
			$expireDate = (Get-Date).AddSeconds($blockPeriod)
		}
		if (Test-RuleExists $IP) {
			Write-LogWarning ("IP $IP already blocked.")
		} else {
			Add-FirewallRule $IP $expireDate
		}
	}
}

# Unban the IP (with checking)
function Unlock-Address ($IP) {
	if (!(Test-RuleExists $IP)) {
		Write-LogDebug "$IP firewall listing doesn't exist. Can't remove it. "
	} else {
		Remove-FirewallRule $IP
	}
}

# Add the Firewall Rule
function Add-FirewallRule ($IP, $expireDate) {
	$expire = (Get-Date $expireDate -format u).replace("Z","")
	switch($BLOCK_TYPE) {
		# External apps and cmdlets receive arguments in differents ways
		# That's why using 2 different tables
		"NETSH" {
			$addRuleExec = 'netsh'
			$addRuleExecArgs = @(
				"advfirewall", "firewall", "add", "rule",
				"name=", "$FirewallRulePrefix $IP",
				"dir=", "in",
				"protocol=", "any",
				"action=", "block",
				"remoteip=", $IP,
				"description=", "Expire: $expire"
			)
			$addRuleCmdletArgs = @{}
		}
		"MIKROTIK" {
			$addRuleExec = 'Send-Mikrotik'
			$addRuleExecArgs = @()
			$addRuleCmdletArgs = @{
				Connection = $mikroConnection
				Command = "/ip/firewall/address-list/add"
				# Mikrotik address-list has the TIMEOUT argument
				# But will not use it
				# Let the rule be deleted by script which created it
				Attributes = @("comment=Expire: $expire",
							"list=$addrListName",
							"address=$IP"
				)
			}
		}
		default { Write-LogError "Cannot add rule. Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($addRuleExec) {
		$result = & $addRuleExec @addRuleExecArgs @addRuleCmdletArgs
		if ($LASTEXITCODE -eq 0) {
			$blockedMessage = "Action Successful: Firewall rule added for $IP, expiring on $expireDate"
			Write-LogAction "$blockedMessage"
			Register-Event "$blockedMessage" ADD OK
		} else {
			$message = "Action Failure: could not add firewall rule for $IP,	error: `"$result`". Return code: $LASTEXITCODE"
			Write-LogError $message
			Register-Event $message ADD FAIL
		}
	}
}

# Remove the Filewall Rule
function Remove-FirewallRule ($IP) {
	switch($BLOCK_TYPE) {
		"NETSH" {
			$removeRuleExec = 'netsh'
			$removeRuleExecArgs = @(
				"advfirewall", "firewall", "delete", "rule",
				"name=", "$FirewallRulePrefix $IP"
			)
			$removeRuleCmdletArgs = @{}
		}
		"MIKROTIK" {
			$removeRuleExec = 'Send-Mikrotik'
			$removeRuleExecArgs = @()
			$removeRuleCmdletArgs = @{
					Connection 	= $mikroConnection
					Command 	= "/ip/firewall/address-list/print"
					Filters		= "address=$IP"
			}
			$getID = & $removeRuleExec @removeRuleCmdletArgs
			foreach ($string in $getID) {
				if ($string -match "^\.id=(?<ID>.*?)=.*") {
					$removeRuleCmdletArgs.Remove("Filters")
					$removeRuleCmdletArgs.Add("Attributes", "numbers=$($matches.ID)")
					$removeRuleCmdletArgs["Command"] = "/ip/firewall/address-list/remove"
				}
			}
		}
		default { Write-LogError "Cannot remove rule. Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($removeRuleExec) {
		$result = & $removeRuleExec @removeRuleExecArgs @removeRuleCmdletArgs
		if ($LASTEXITCODE -eq 0) {
			Write-LogAction "Action Successful: Firewall ban for $IP removed"
			Register-Event "Removed IP $IP from firewall rules"	REMOVE OK
		} else {
			$message = "Action Failure: could not remove firewall rule for $IP,	error: `"$result`". Return code: $LASTEXITCODE"
			Write-LogError $message
			Register-Event $message REMOVE FAIL
		}
	}
}

# Remove any expired bans
function Unblock-ExpiredRecords {
	# Read blockList from firewall rules
	$currentBlockList = Read-BlockList
	if ($currentBlockList) {
		foreach ($record in $currentBlockList.GetEnumerator()) {
			$IP = $($record.Name)
			$releaseDate = $($record.Value)

			if ($([int]([datetime]$releaseDate- (Get-Date)).TotalSeconds) -lt 0) {
				Write-LogDebug "Unban old records: $IP looks old enough $(Get-Date $releaseDate -format G)"
				Unlock-Address $IP
			}
		}
	}
}

 #Convert the TimeGenerated time into Epoch
function WMIDateStringToDateTime( [String] $iSt ) {
	$iSt.Trim() > $null
	$iYear	 = [Int32]::Parse($iSt.SubString( 0, 4))
	$iMonth	= [Int32]::Parse($iSt.SubString( 4, 2))
	$iDay		= [Int32]::Parse($iSt.SubString( 6, 2))
	$iHour	 = [Int32]::Parse($iSt.SubString( 8, 2))
	$iMinute = [Int32]::Parse($iSt.SubString(10, 2))
	$iSecond = [Int32]::Parse($iSt.SubString(12, 2))
	$iMilliseconds = 0 
	$iUtcOffsetMinutes = [Int32]::Parse($iSt.Substring(21, 4))
	if ( $iUtcOffsetMinutes -ne 0 )	{ $dtkind = [DateTimeKind]::Local }
		else { $dtkind = [DateTimeKind]::Utc }
	$ReturnDate =	New-Object -TypeName DateTime `
		-ArgumentList $iYear, $iMonth, $iDay, $iHour, $iMinute, $iSecond, $iMilliseconds, $dtkind
	return (Get-Date $ReturnDate -UFormat "%s")
}


# Remove recorded access attempts, by IP, or expired records if no IP provided.
function Reset-AttemptCount ($IP = 0) {
	$removalList = @()
	# structure: eventRecord = { $RecordID, @($IP,$EventDate) }
	ForEach ($eventRecord in $eventsTable.GetEnumerator()) {
		if ($IP -eq 0) {
		if ([int]$eventRecord.Value[1]+$CHECK_WINDOW -lt (Get-Date ((Get-Date).ToUniversalTime()) -UFormat "%s").replace(",",".")) {
			$removalList += $eventRecord.Key
		}
		} else {
		ForEach ($eventRecord in $eventsTable.GetEnumerator()) {
			if ($eventRecord.Value[0] -eq $IP) {	$removalList += $eventRecord.Key }
		}
		}
	}
	ForEach ($entry in $removalList) { $eventsTable.Remove($entry)}
}

# Open connection to Miktotik, check if blocking rule exists
# If connection could not be established quit script entirely
function Open-MikrotikConnection {
	Try {
		Import-Module $mikroModulePath -ErrorAction Stop
	} Catch {
		$message = $_.Exception.Message
		Write-LogError $message
	}

	$execCmd = 'Connect-Mikrotik'
	$execParams = @{
		IPAddress	= $mikroIP
		UserName	= $mikroUser
		Password	= $mikroPassword
	}
	if ($mikroSSL -eq "yes") { $execParams.Add("UseSSL", $true) }
		else { $execParams.Add("UseSSL", $false) }
	$mikroConnectionLocal = & $execCmd @execParams
	if (!$mikroConnectionLocal) {
		Write-LogError "Could not connect to Mikrotik at $mikroIP"
		exit 1
	}

	# Check existance of autogenerated rule
	$execCmd = 'Send-Mikrotik'
	$execParams = @{
		Connection = $mikroConnectionLocal
		Command = "/ip/firewall/filter/print"
		Filters = "comment=wail2ban autocreated rule"
	}
	$result = & $execCmd @execParams
	if (!$result) {
		Write-Host "No autorule, creating one."
		$execCmd = 'Send-Mikrotik'
		$execParams = @{
			Connection = $mikroConnectionLocal
			Command = "/ip/firewall/filter/add"
			Attributes = @("comment=wail2ban autocreated rule",
						"chain=forward",
						"action=drop",
						"src-address-list=wail2ban",
						"place-before=0")
		}
		$createRule = & $execCmd @execParams
		
		# Command ADD returns smth ony in case of error
		if ($createRule) {
			Write-LogError "Could not create rule, something wrong."
			Disconnect-Mikrotik -Connection $mikroConnection
			Write-LogDebug "Removing module"
			Remove-Module $moduleName
			exit 1
		}
	}
	return $mikroConnectionLocal
}
# // Open-MikrotikConnection

if ($BLOCK_TYPE -eq "MIKROTIK") { $mikroConnection = Open-MikrotikConnection }

################################################################################
## Process input parameters
# if ($setting) { debug "wail2ban started. $setting" }

# Display current configuration.
if ($args -match "-config") {
	Write-Host "`nwail2ban is currently configured to: `n ban IPs for " -nonewline
	for ($i = 1; $i -lt 5; $i++) { Write-Host (""+[math]::pow(5,$i)+", ") -foregroundcolor "cyan" -nonewline }
	Write-Host "... $($MAX_BANDURATION/60) " -foregroundcolor "cyan" -nonewline
	Write-Host " minutes, `n if more than " -nonewline
	Write-Host $CHECK_COUNT -foregroundcolor "cyan" -nonewline
	Write-Host " failed attempts are found in a " -nonewline
	Write-Host $CHECK_WINDOW -foregroundcolor "cyan" -nonewline
	Write-Host " second window. `nThis process will loop every time a new record appears. "
	Write-Host "`nIt's currently checking:"
	foreach ($event in $CheckEvents ) {	"- "+$Event.EventLog+" event log for event ID "+$Event.EventDescription+" (Event "+$Event.EventID+")"}
	Write-Host "`nAnd we're whitelisting: "
	foreach ($whitelistEntry in $whitelist) {
		Write-Host "- $($whitelistEntry)" -foregroundcolor "cyan" -nonewline
	}
	Write-Host "in addition to any IPs present on the network interfaces on the machine"
	exit
}

# Release all current banned IPs
if ($args -match "-jailbreak") {
	Write-LogAction "Jailbreak initiated by console. Removing ALL IPs currently banned"
	$EnrichmentCentre = Read-BlockList
	if ($EnrichmentCentre){
		"`nAre you trying to escape? [chuckle]"
		"Things have changed since the last time you left the building."
		"What's going on out there will make you wish you were back in here."
		" "
		foreach ($subject in $EnrichmentCentre.GetEnumerator()) { 
			$IP = $($subject.Name)
			Remove-FirewallRule $IP
		}
		Clear-Content $BannedIPLog
	} else { "`nYou can't escape, you know. `n`n(No current firewall listings to remove.)" }
	exit
}

# Show the records in the jail.
if ($args -match "-jail") {
	$records = Read-BlockList
	if ($records) { 
		"wail2ban currently banned listings: `n"
		foreach ($record in $records.GetEnumerator()) {
			""+$record.Name.PadLeft(14)+" expires at $($record.Value)"
		}
		"`nThis is a listing of the current Windows Firewall with Advanced Security rules, starting with `""+$FirewallRulePrefix+" *`""
	} else { "There are no currrently banned IPs"}
	exit
}

# Unban specific IP. Remove associated schtask, if exists.
if ($args -match "-unban") {
	$IP = $args[ [array]::indexOf($args,"-unban")+1] 
	Write-LogAction "Unban IP invoked: going to unban $IP and remove from the log."
	Unlock-Address $IP
	(Get-Content $BannedIPLog) | Where-Object {$_ -notmatch $IP } | Set-Content $BannedIPLog # remove IP from ban log
	exit
}

#Display Help Message
if ($args -match "-help") {
	help;	exit
}

################################################################################
#Setup for the loop

$sinkName = "LoginAttempt"
$eventsTable = @{}
$eventlist ="("
foreach($a in $CheckEvents) {
	$eventlist+="(TargetInstance.EventCode=$($a.EventID) and TargetInstance.LogFile='$($a.EventLog)') OR "
}
$eventlist = $eventlist.substring(0,$eventlist.length-4)+")"
$query = "SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND $eventlist"

Write-LogAction "wail2ban invoked"
Write-LogAction "Checking for a heap of events: "
$CheckEvents | ForEach-Object { Write-LogAction " - $($_.EventLog) log event code $($_.EventID)" }
Write-LogAction "The Whitelist: $whitelist"
Write-LogAction "The Self-list: $Selflist"

Read-BlockPeriodLog

################################################################################
#Loop!
try {
	Register-WMIEvent -Query $query -sourceidentifier $sinkName
	do {
		$occurredEvent = Wait-Event -sourceidentifier $sinkName -Timeout 120
		if ($occurredEvent) {
			$eventInstance = $occurredEvent.SourceEventArgs.NewEvent.TargetInstance
			Select-String $RegexIP -input $eventInstance.message -AllMatches | ForEach-Object { foreach ($address in $_.matches) {
				$IP = $address.Value
				if ($SelfList -match $IP) {
					Write-LogDebug "Whitelist of self-listed IPs! Do nothing. ($IP)"
				} else {
					$RecordID = $eventInstance.RecordNumber
					$EventDate = WMIDateStringToDateTime($eventInstance.TIMEGenerated)
					$eventsTable.Add($RecordID, @($IP,$EventDate))

					$IPCount = 0
					foreach ($value in $eventsTable.Values) {
						if ($IP -eq $value[0]) { $IPCount++ }
					}
					Write-LogDebug "$($eventInstance.LogFile) Write-Log Event captured: ID $($RecordID), IP $IP, Event Code $($eventInstance.EventCode), Attempt #$($IPCount). "

					if ($IPCount -ge $CHECK_COUNT) {
						Block-Address $IP
						Reset-AttemptCount $IP
					}
					Reset-AttemptCount				
				}
			}
			}
			Remove-Event -sourceidentifier $sinkName
		}
		Unblock-ExpiredRecords
	} while ($true)
}
catch {
	Write-LogError $_.Exception.Message
}
finally {
	# If smth goes wrong and script terminating do not forget to close connection and event sink
	if ($BLOCK_TYPE -eq "MIKROTIK") {
		Write-LogDebug "Disconnecting Mikrotik."
		Disconnect-Mikrotik -Connection $mikroConnection
		Write-LogDebug "Removing module."
		Remove-Module $mikroModuleName
	}
	Write-LogDebug "Unregistering sink."
	Unregister-Event -SourceIdentifier $sinkName
}