<#  
     .NOTES
===========================================================================
    ## License ##    

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details. 
===========================================================================

Created by:    Andrew Matthews
Organization:  To The Cloud And Beyond
Filename:      BootStrap.ps1
Documentation: https://tothecloudandbeyond.substack.com/
Execution Tested on: Windows 10 2009
Requires:      Installation from Intune with an App package
Versions:
1.0 Initial Release
 - Initial release focused on building a platform for complex application installations
1.1 Bug fix
 - Fixed an issue with the reboot protocol not being added 
 
===========================================================================
.SYNOPSIS
The execution engine for the bootstrap of the installation package. The installation package allows complex installations of apps 
.DESCRIPTION
The bootstrap performs the following actions.
# Section 1
 - Script Initialisation
 - Create the log file
# SECTION 2 
 - Secures the secure scripts folder
# Section 3 
 - Deploys scheduled tasks for post deployment

.INPUTS
The execution engine is controled by a config file (config.xml). Some areas of the script reference additional config files

.OUTPUTS
A log file in C:\Program Files\Deploy\DeployLog

#>

################################################
#Declare Constants and other Script Variables
################################################

#Set the Install folder
$InstallFolder = "$PSScriptRoot\"

$MarkerName = ""

#Log Levels
[string]$LogLevelError = "Log_Error"
[string]$LogLevelWarning = "Log_Warning"
[string]$LogLevelInfo = "Log_Information"

[string]$LogPath = "C:\Program Files\Deploy\DeployLog"
[string]$TxtLogfilePrefix = "UpdateNotificationBootstrap" # Log file in cmtrace format

$LogCacheArray = New-Object System.Collections.ArrayList
$MaxLogCachesize = 10
$MaxLogWriteAttempts = 5

$DebugScript = $false
$LogWriteScreen = $true

$TaskExecutableType_WScript = "WScript"
$TaskExecutableType_PowerShell = "PowerShell"

$WScriptpath = "C:\WINDOWS\system32\wscript.exe"

#Set the MSIExec path
$MSIExecPath = "C:\Windows\System32\msiexec.exe"
#Set the maximum number of MSI installation attempts
$MSIMaxInstallAttempts = 5
#Set a delay time for waits between MSI installation attempts
$MSIInstallDelay = 120

if($DebugScript -eq $true) {
    Start-Transcript -Path "C:\Program Files\Deploy\DeployLog\UpdateNotificationBootstrapTranscript.txt"
}

$ProcessToastProtocols = $True

################################################
#Declare Functions
################################################

<# Create a New log entry and invoke the log cache flush if required #>
Function New-LogEntry {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$LogEntry,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Log_Error","Log_Warning","Log_Information")]
        [string]$LogLevel,
        [Parameter(Mandatory=$false)]
        [Bool]$ImmediateLog,
        [Parameter(Mandatory=$false)]
        [Bool]$FlushLogCache
    )

    #Create the CMTrace Time stamp
    $TxtLogTime = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $TxtLogDate = "$(Get-Date -Format MM-dd-yyyy)"

    #Create the Script line number variable
    $ScriptLineNumber = "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)"

    #Add the log entry to the cache
    switch ($LogLevel) {
        $LogLevelError {  
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevel
        }
        $LogLevelWarning { 
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevel
        }
        $LogLevelInfo { 
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevel
        }
        default {
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevelInfo
        }
    }

    #Set the Write log entries to the default state of false
    $WriteLogEntries = $True
    #Determine whether the log needs to be immediately written
    If ($PSBoundParameters.ContainsKey('ImmediateLog')) {
        If($ImmediateLog -eq $false) {
            #Do not invoke the log flush       
        } Else {
            #If the action is immediate log then flush the log entries
            $WriteLogEntries = $True
        }
    } else {
        #If no value specified then for not flush the log cache
        $WriteLogEntries = $false
    }

    If ($PSBoundParameters.ContainsKey('FlushLogCache')) { 
        If($FlushLogCache -eq $false) {
            If($LogCacheArray.count -eq $MaxLogCachesize) {
                #If the max cache size has been hit then flush the log entries
                $WriteLogEntries = $true
            }
        } else { 
            $WriteLogEntries = $true
        }
    } else {
        If($LogCacheArray.count -eq $MaxLogCachesize) {
            #If the max cache size has been hit then flush the log entries
            $WriteLogEntries = $true
        }
    }


    If ($WriteLogEntries -eq $true) {
        #write the log entries
        Write-LogEntries
    }
    If ($LogWriteScreen -eq $true) {
        Write-Host $LogEntry
    }
}

<# Write the log entries to the log file #>
Function Write-LogEntries {
    Write-Host "**** Flushing $($LogCacheArray.count) Log Cache Entries ****"
    $LogTextRaw = ""
    #Rotate through the Log entries and compile a master variable
    ForEach($LogEntry in $LogCacheArray) {
        switch ($LogEntry.LogLevel) {
            $LogLevelError {  
                #Create the CMTrace Log Line
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 3 + '" thread="" file="">'
            }
            $LogLevelWarning {
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 2 + '" thread="" file="">'
            }
            $LogLevelInfo {
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
            }
            default {
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
            }
        }
        If($LogTextRaw.Length -eq 0) {
            $LogTextRaw = $TXTLogLine
        } else {
            $LogTextRaw = $LogTextRaw + "`r`n" + $TXTLogLine
        }
    }

    #Write the Log entries Log line
    $LogWritten = $false
    $LogWriteAttempts = 0
    do {
        $LogWriteAttempts = $LogWriteAttempts + 1
        $WriteLog = $True
        Try {
            Add-Content -Value $LogTextRaw -Path $TxtLogFile -ErrorAction Stop
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            $WriteLog = $false
            Write-Host "Log entry flush failed"
            Write-Host $ErrorMessage
        }
        If ($WriteLog-eq $false) {
            If ($LogWriteAttempts -eq $MaxLogWriteAttempts) {
                Write-Host "Maximum log write attempts exhausted - saving log entries for the next attempt"
                $LogWritten = $true
            }
            #Wait five seconds before looping again
            Start-Sleep -Seconds 5
        } else {
            $LogWritten = $true
            Write-Host "Wrote $($LogCacheArray.count) cached log entries to the log file"
            $LogCacheArray.Clear()
        }
    } Until ($LogWritten -eq $true) 
        
}

<# Create a new entry in the log cache #>
Function New-LogCacheEntry {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$LogEntry,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Log_Error","Log_Warning","Log_Information")]
        [string]$LogLevel,
        [Parameter(Mandatory=$true)]
        [string]$LogTime,
        [Parameter(Mandatory=$true)]
        [string]$LogDate,
        [Parameter(Mandatory=$true)]
        [string]$ScriptLineNumber
    )

    $LogCacheEntry = New-Object -TypeName PSObject -Property @{
        'LogEntry' = $LogEntry
        'LogLevel' = $LogLevel
        'LogTime' = $LogTime
        'LogDate' = $LogDate
        'Linenumber' = $ScriptLineNumber
    }

    $LogCacheArray.Add($LogCacheEntry) | Out-Null

}

<# Create a new log file for a Txt Log #>
Function New-TxtLog {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$NewLogPath,
        [Parameter(Mandatory=$true)]    
        [string]$NewLogPrefix
    )

    #Create the log path if it does not exist
    if (!(Test-Path $NewLogPath))
    {
        New-Item -itemType Directory -Path $NewLogPath
    }

    #Create the new log name using the prefix
    [string]$NewLogName = "$($NewLogPrefix)-$(Get-Date -Format yyyy-MM-dd)-$(Get-Date -Format HH-mm).log"
    #Create the fill path
    [String]$NewLogfile = Join-Path -path $NewLogPath -ChildPath $NewLogName
    #Create the log file
    New-Item -Path $NewLogPath -Name $NewLogName -Type File -force | Out-Null

    #Return the LogfileName
    Return $NewLogfile
}

<# Exit the script#>
Function Exit-Script {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$ExitText
    )
    
    #Write the exit text to the log, flush the log cache and exit
    New-LogEntry -LogEntry $ExitText -FlushLogCache $true
    Exit
}

<# Check whether task triggers match#>
Function Find-TaskTriggerMatch {
   
    param (
        [Parameter(Mandatory=$true)]$TriggerArray,
        [Parameter(Mandatory=$true)]$Existing
    )
    
    New-LogEntry -LogEntry "@@@ Starting Trigger Match @@@"
    New-LogEntry -LogEntry "-------------------------------"
    New-LogEntry -LogEntry "Existing Triggers: $($Existing.count) - Triggers $($TriggerArray.count)"
    New-LogEntry -LogEntry "-------------------------------"
    #Set the matched triggers counter
    $MatchedTriggers = 0
    #Check the Daily triggers for the existing task
    $DailyExistingTriggersExists = $True
    try {
        $DailyExistingTriggers = $Existing | where-object {$_ -match "MSFT_TaskDailyTrigger"}
    } catch {
        $DailyExistingTriggersExists = $false
        New-LogEntry -LogEntry "No Daily Existing Triggers found (Catch)"
    }
    if ($DailyExistingTriggersExists -eq $True) {
        If($null -eq $DailyExistingTriggers) { 
            New-LogEntry -LogEntry "No Daily Existing Triggers found (null)"
            $DailyExistingTriggersExists = $false
        } else {
            if($DailyExistingTriggers.gettype().name -eq "CimInstance") {
                New-LogEntry -LogEntry "Daily Existing Trigger Count single"
            } else {
                if($DailyExistingTriggers.Count -eq 0) {
                    New-LogEntry -LogEntry "No Daily Existing Triggers found"
                    $DailyExistingTriggersExists = $false
                } else {
                    New-LogEntry -LogEntry "Daily Existing Trigger Count: $($DailyExistingTriggers.Count)"
                }
            }
        }
    }

    #Check the Daily task triggers for the task array
    $DailyTriggersExists = $True
    try {
        $DailyTriggers = $TriggerArray | where-object {$_ -match "MSFT_TaskDailyTrigger"}
    } catch {
        $DailyTriggersExists = $false
        New-LogEntry -LogEntry "No Daily Triggers found (Catch)"
    }
    If($DailyTriggersExists -eq $True) {
        If($null -eq $DailyTriggers) { 
            New-LogEntry -LogEntry "No Daily Triggers found (null)"
            $DailyTriggersExists = $false
        } else {
            if($DailyTriggers.gettype().name -eq "CimInstance") {
                New-LogEntry -LogEntry "Daily Trigger Count single"
            } else {
                if($DailyTriggers.Count -eq 0) {
                    New-LogEntry -LogEntry "No Daily Triggers found"
                    $DailyTriggersExists = $false
                } else {
                    New-LogEntry -LogEntry "Daily Trigger Count: $($DailyTriggers.Count)"
                }
            }
            
        }
    }
    
    #Match the daily tasks
    If (($DailyExistingTriggersExists -eq $True) -and ($DailyTriggersExists -eq $True) ) {
        New-LogEntry -LogEntry "Checking Daily Triggers"
        Foreach($DailyTrigger in $DailyTriggers) {
            #Set the Trigger match value
            $MatchFound = $False
            Foreach($DailyExistingTrigger in $DailyExistingTriggers) {
                If(($DailyExistingTrigger.startboundary.hour -eq $DailyTrigger.startboundary.hour) -and ($DailyExistingTrigger.startboundary.minutes -eq $DailyTrigger.startboundary.minutes) -and ($DailyExistingTrigger.startboundary.seconds -eq $DailyTrigger.startboundary.seconds) -and ($DailyExistingTrigger.DaysInterval -eq $DailyTrigger.DaysInterval)) {
                    if($DailyExistingTrigger.Enabled -eq $true) {
                        $MatchFound = $True
                    }
                }
            }
            if($MatchFound -eq $true) {
                #Increment the matches found
                $MatchedTriggers = $MatchedTriggers + 1
            }
        }
    }
    #Check the Weekly triggers for the existing task
    $WeeklyExistingTriggersExists = $True
    try {
        $WeeklyExistingTriggers = $Existing| where-object {$_ -match "MSFT_TaskWeeklyTrigger"}
    } catch {
        $WeeklyExistingTriggersExists = $false
        New-LogEntry -LogEntry "No Weekly Existing Triggers found (Catch)"
    }
    if ($WeeklyExistingTriggersExists -eq $True) {
        If($null -eq $WeeklyExistingTriggers) { 
            New-LogEntry -LogEntry "No Weekly Existing Triggers found (null)"
            $WeeklyExistingTriggersExists = $false
        } else {
            if($WeeklyExistingTriggers.gettype().name -eq "CimInstance") {
                New-LogEntry -LogEntry "Weekly Existing Trigger Count single"
            } else {
                if($WeeklyExistingTriggers.Count -eq 0) {
                    New-LogEntry -LogEntry "No Weekly Existing Triggers found"
                    $WeeklyExistingTriggersExists = $false
                } else {
                    New-LogEntry -LogEntry "Weekly Existing Trigger Count $($WeeklyExistingTriggers.Count)"
                }
            }
        }
    }

    #Check the Weekly task triggers for the task array
    $WeeklyTriggersExists = $True
    try {
        $WeeklyTriggers = $TriggerArray | where-object {$_ -match "MSFT_TaskWeeklyTrigger"}
    } catch {
        $WeeklyTriggersExists = $false
        New-LogEntry -LogEntry "No Weekly Triggers found (Catch)"
    }
    If($WeeklyTriggersExists -eq $True) {
        If($null -eq $WeeklyExistingTriggers) { 
            New-LogEntry -LogEntry "No Weekly Triggers found (null)"
            $WeeklyTriggersExists = $false
        } else {
            if($WeeklyTriggers.gettype().name -eq "CimInstance") {
                New-LogEntry -LogEntry "Weekly Trigger Count single"
            } else {
                if($WeeklyTriggers.Count -eq 0) {
                    New-LogEntry -LogEntry "No Weekly Triggers found"
                    $WeeklyTriggersExists = $false
                } else {
                    New-LogEntry -LogEntry "Weekly Trigger Count $($WeeklyTriggers.Count)"
                }
            }
        }
    }
    #Match the weekly tasks
    If (($WeeklyExistingTriggersExists -eq $True) -and ($WeeklyTriggersExists -eq $True) ) {
        Foreach($WeeklyTrigger in $WeeklyTriggers) {
            #Set the Trigger match value
            New-LogEntry -LogEntry "Checking Weekly Triggers"
            $MatchFound = $False
            Foreach($WeeklyExistingTrigger in $WeeklyExistingTriggers) {
                If(($WeeklyExistingTrigger.startboundary.hour -eq $WeeklyTrigger.startboundary.hour) -and ($WeeklyExistingTrigger.startboundary.minutes -eq $WeeklyTrigger.startboundary.minutes) -and ($WeeklyExistingTrigger.startboundary.seconds -eq $WeeklyTrigger.startboundary.seconds) -and ($WeeklyExistingTrigger.WeeksInterval -eq $WeeklyTrigger.WeeksInterval)) {
                    if($WeeklyExistingTrigger.Enabled -eq $true) {
                        $MatchFound = $True
                    }
                }
            }
            if($MatchFound -eq $true) {
                #Increment the matches found
                $MatchedTriggers = $MatchedTriggers + 1
            }
        }
    }

    #Check the At logon triggers for the existing task
    $AtLogonExistingTriggersExists = $True
    try {
        $AtLogonExistingTriggers = $Existing| where-object {$_ -match "MSFT_TaskLogonTrigger"}
    } catch {
        $AtLogonExistingTriggersExists = $false
        New-LogEntry -LogEntry "No At Logon Existing Triggers found (Catch)"
    }
    if ($AtLogonExistingTriggersExists -eq $True) {
        If($null -eq $AtLogonExistingTriggers) { 
            New-LogEntry -LogEntry "No At Logon Existing Triggers found (null)"
            $AtLogonExistingTriggersExists = $false
        } else {
            if($AtLogonExistingTriggers.gettype().name -eq "CimInstance") {
                New-LogEntry -LogEntry "At Logon Existing Trigger Count single"
            } else {
                if($AtLogonExistingTriggers.Count -eq 0) {
                    New-LogEntry -LogEntry "No At Logon Existing Triggers found"
                    $AtLogonExistingTriggersExists = $false
                } else {
                    New-LogEntry -LogEntry "At Logon Existing Trigger Count $($AtLogonExistingTriggers.Count)"
                }
            }
        }
    }

    #Check the AtLogon task triggers for the task array
    $AtLogonTriggersExists = $True
    try {
        $AtLogonTriggers = $TriggerArray | where-object {$_ -match "MSFT_TaskLogonTrigger"}
    } catch {
        $AtLogonTriggersExists = $false
        New-LogEntry -LogEntry "No At Logon Triggers found (Catch)"
    }
    If($AtLogonTriggersExists -eq $True) {
        If($null -eq $AtLogonExistingTriggers) { 
            New-LogEntry -LogEntry "No At Logon Triggers found (null)"
            $AtLogonTriggersExists = $false
        } else {
            if($AtLogonTriggers.gettype().name -eq "CimInstance") {
                New-LogEntry -LogEntry "At Logon Trigger Count single"
            } else {
                if($AtLogonTriggers.Count -eq 0) {
                    New-LogEntry -LogEntry "No At Logon Triggers found"
                    $AtLogonTriggersExists = $false
                } else {
                    New-LogEntry -LogEntry "At Logon Trigger Count $($AtLogonTriggers.Count)"
                }
            }
        }
    }

    If (($AtLogonExistingTriggersExists -eq $True) -and ($AtLogonTriggersExists -eq $True) ) {
        Foreach($AtLogonTrigger in $AtLogonTriggers) {
            New-LogEntry -LogEntry "Checking At Logon Triggers"
            #Set the Trigger match value
            $MatchFound = $False
            Foreach($AtLogonExistingTrigger in $AtLogonExistingTriggers) {
                if($AtLogonExistingTrigger.Enabled -eq $true) {
                    $MatchFound = $True
                }
            }
            if($MatchFound -eq $true) {
                #Increment the matches found
                $MatchedTriggers = $MatchedTriggers + 1
            }
        }
    }


    #Work out whether the Triggers matched
    New-LogEntry -LogEntry "Matched Triggers: $($MatchedTriggers) - Configured Triggers: $($TriggerArray.count)"
    If($MatchedTriggers -eq $TriggerArray.count) {
        $TriggerMatch = $True
    } else {
        $TriggerMatch = $False
    }
    New-LogEntry -LogEntry "@@@ Ending Trigger Match @@@"
    Return $TriggerMatch
} 

<# Install an MSI file#>
Function Install-MSI {

    Param (
        [Parameter(Mandatory=$true)]
        [String]$MSI,
        [Parameter(Mandatory=$true)]
        $MSIArguments
    )

    #Set the return value
    $FunctionStatus = $True

    #Create the arguments for the install
    New-LogEntry -logentry "Compiling MSI installation options"

    $MSIInstallArguments = New-Object System.Collections.ArrayList
    $MSIInstallArguments.Add("/i")
    $MSIInstallArguments.Add("`"$($MSI)`"")
    
    #Add the arguments
    .{
        Foreach($MSIArgument in $MSIArguments) {
            $MSIInstallArguments.Add($MSIArgument) | Out-Null
        }
    }

    New-LogEntry -LogEntry "MSI Installation options - $($MSIInstallArguments)"

    

    $MSIInstallAttempts = 0
    $MSIInstallAttemptsComplete = $false
    
    #Loop through attempts to install the MSI file
    Do {
        #Increment the MSI installation attempt count
        $MSIInstallAttempts = $MSIInstallAttempts + 1
        New-LogEntry -LogEntry "Starting MSI installation attempt $($MSIInstallAttempts)"
        
        #Invoke the MSI installation
        $InstallMsiOk = Invoke-Process -Executable $MSIExecPath -Arguments $MSIInstallArguments
        If ($InstallMsiOk.Status -eq $True) {
            New-LogEntry -LogEntry "MSI Installation succeeded"
            #Set the exit condition
            $MSIInstallAttemptsComplete = $True
        } else {
            #If the exit code is 1618 - MSI installation in progress then wait and retry
            If($InstallMsiOk.ExitCode -eq 1618) {
                If ($MSIInstallAttempts -eq $MSIMaxInstallAttempts) {
                    New-LogEntry -LogEntry "MSI Install attempts exceeded. Aborting installation"
                    $FunctionStatus = $False
                    #Set the exit condition
                    $MSIInstallAttemptsComplete = $True
                } else {
                    New-LogEntry -LogEntry "Another installation is in progress. Waiting for the other installation to complete" -FlushLogCache $true
                    Start-Sleep -Seconds $MSIInstallDelay
                }
            } else {
                New-LogEntry -LogEntry "MSI Installation failed - Exit code $($InstallMsiOk.ExitCode)"
                $FunctionStatus = $False
                #Set the exit condition
                $MSIInstallAttemptsComplete = $True
            }
        }
       
    } until ($MSIInstallAttemptsComplete -eq $true)

    

    Return $FunctionStatus
}

<# Invoke a process with wait #>
Function Invoke-Process {
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$Executable,
        [Parameter(Mandatory=$false)]$Arguments,
        [Parameter(Mandatory=$false)][Bool]$NoNewWindow
    )
    $filepath = "`"$Executable`""
    New-LogEntry -LogEntry "Running invoke process for $($filepath)"
    #Set the output files variables
    $stdOutTempFile = "$env:TEMP\$((New-Guid).Guid)"
    New-LogEntry -LogEntry "Outputting standard out to $($stdOutTempFile)"
    $stdErrTempFile = "$env:TEMP\$((New-Guid).Guid)"
    New-LogEntry -LogEntry "Outputting standard err to $($stdErrTempFile)"

    #Create the hash table
    $ProcessParameters = @{
        FilePath = $filepath
        RedirectStandardError = $stdErrTempFile
        RedirectStandardOutput = $stdOutTempFile
        Wait = $true;
        PassThru = $true;
    }

    #Set the status variable
    $ReturnValue = [PSCustomObject]@{
        'Status' = $true
        'ExitCode' = ""
    }

    #Construct the process arguments
    If(!($null -eq $Arguments)) {
        switch ($Arguments.GetType().Name) {
            "String" { 
                If(!($Arguments.Length -eq 0)) {
                    $ProcessParameters.Add("ArgumentList",$Arguments)
                }
            }
            "Object[]" {
                $ProcessParameters.Add("ArgumentList",$Arguments)
                New-LogEntry -LogEntry "Arguments supplied as an object"
                New-LogEntry -LogEntry "Arguments $($ProcessParameters.ArgumentList)"
            }
            "ArrayList" {
                $ProcessParameters.Add("ArgumentList",$Arguments)
                New-LogEntry -LogEntry "Arguments supplied as an arraylist"
                New-LogEntry -LogEntry "Arguments $($ProcessParameters.ArgumentList)"
            }
            Default {
                New-LogEntry -LogEntry "Unknown argument type supplied"
                $ReturnValue.Status = $false
            }
        }
    }

    #Set the window state
    If(!($null -eq $NoNewWindow)) {
        If($NoNewWindow -eq $False) {
            $ProcessParameters.Add("NoNewWindow",$false)
        } else {
            $ProcessParameters.Add("NoNewWindow",$true)
        }
    } else {
        $ProcessParameters.Add("NoNewWindow",$true)
    }

    #Start the process
    Try {
        $Process = Start-Process @ProcessParameters
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Process invoke failed"
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
    }
    #Check the contents of the output files
    $ProcessOutput = Get-Content -Path $stdOutTempFile -Raw
    $ProcessError = Get-Content -Path $stdErrTempFile -Raw
    if($Process.ExitCode -eq 0) {
        New-LogEntry -LogEntry "The process invoke succeeded"
        $ReturnValue.Status = $true
        if ([string]::IsNullOrEmpty($ProcessOutput) -eq $false) {
            New-LogEntry -LogEntry $ProcessOutput 
        }
    }elseif ($Process.ExitCode -ne 0) {
        $ReturnValue.Status = $False
        New-LogEntry -LogEntry "The process invoke failed with exit code $($Process.ExitCode)"
        $ReturnValue.ExitCode = $Process.ExitCode
        if ($ProcessError) {
            New-LogEntry -LogEntry $ProcessError -LogLevel $LogLevelWarning 
        }
        if ($cmdOutput) {
            New-LogEntry -LogEntry $ProcessOutput -LogLevel $LogLevelWarning 
            throw $ProcessOutput.Trim()
        }
    } else {
        if ([string]::IsNullOrEmpty($ProcessOutput) -eq $false) {
            New-LogEntry -LogEntry $ProcessOutput 
        }
    }
    
    #Remove the output files
    #Remove-Item -Path $stdOutTempFile, $stdErrTempFile -Force -ErrorAction Ignore
    Return $ReturnValue
    
}

<#
Setup the toast protocols
#>
Function Set-ToastProtocols {

    #Create the return object
    $FunctionStatus = [PSCustomObject]@{
        "Status" = $True
        "Error" = ""
    }

    #Create a PS Drive for HKEY Current User
    Try{
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null 
    } Catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Creation of a PSDrive for HKCR failed"
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
        $FunctionStatus.Status = $False
    }

    if($FunctionStatus.Status -eq $True) { 
        #Get the child nodes value
        $ProtocolCount = $config.config.Toast.Protocols.ChildNodes.Count
        If($null -eq $ProtocolCount) {
            $FunctionStatus.Status = $True
        } else {
            If($ProtocolCount -eq 0) {
                New-LogEntry -LogEntry "No protocols to process"
            } else {
                New-LogEntry -LogEntry "Processing $($ProtocolCount) protocols"
            }

        }
    }

    #loop through the protocol list
    if(($FunctionStatus.Status -eq $True) -and ($ProtocolCount -gt 0)) {
        $ProtocolsProcessed = 0
        foreach ($Protocol in $config.config.Toast.Protocols.Protocol) {
            $ProtocolOK = $True
            New-LogEntry -LogEntry "Processing Protocol $($Protocol.ID)"

            #Get the registry key for the protocol
            if($ProtocolOK -eq $true){
                if(!($Protocol.Key.Length -eq 0)) {
                    $ProtocolBaseKey = $Protocol.Key
                    #construct the command path
                    $ProtocolCommandKey = Join-Path -path $ProtocolBaseKey -ChildPath "shell\open\command"
                } else {
                    $ProtocolOK = $False
                }
            }

            #Get the default value for the protocol
            if($ProtocolOK -eq $true){
                if(!($Protocol.Default.Length -eq 0)) {
                    $ProtocolDefaultValue = $Protocol.Default
                } else {
                    $ProtocolOK = $False
                }
            }

            #Get the action value for the protocol
            if($ProtocolOK -eq $true){
                if(!($Protocol.Action.Length -eq 0)) {
                    $ProtocolActionValue = $Protocol.Action
                } else {
                    $ProtocolOK = $False
                }            
            }

            #Create the protocol base key
            if($ProtocolOK -eq $true){
                If(Test-path -Path $ProtocolBaseKey) {
                    New-LogEntry -LogEntry "The protocol base path ($($ProtocolBaseKey)) already exists"
                } else {
                    Try {
                        New-Item -Path $ProtocolBaseKey -force -ErrorAction Stop
                    } catch {
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Creation of protocol base path ($($ProtocolBaseKey)) failed"
                        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
                        $ProtocolOK = $False
                    }
                }
            }

            #Create the Protocol Command Key
            if($ProtocolOK -eq $true){
                If(Test-path -Path $ProtocolCommandKey) {
                    New-LogEntry -LogEntry "The protocol base path ($($ProtocolCommandKey)) already exists"
                } else {
                    Try {
                        New-Item -Path $ProtocolCommandKey -force -ErrorAction Stop
                    } catch {
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Creation of protocol base path ($($ProtocolCommandKey)) failed"
                        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
                        $ProtocolOK = $False
                    }
                }
            }

            #Set the default value
            if($ProtocolOK -eq $true){
                Try {
                    New-ItemProperty -Path $ProtocolBaseKey -Name "(Default)" -Value $ProtocolDefaultValue -PropertyType String -ErrorAction Stop -force
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Creation of default registry value ($($ProtocolBaseKey):(Default)) failed"
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
                    $ProtocolOK = $False
                }
            }

            #Set the Edit Flags
            if($ProtocolOK -eq $true){
                Try {
                    New-ItemProperty -Path $ProtocolBaseKey -Name "EditFlags" -Value 2162688 -PropertyType DWORD -ErrorAction Stop -force
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Creation of default registry value ($($ProtocolBaseKey):URL Protocol) failed"
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
                    $ProtocolOK = $False
                }
            }

            #Set the URL Protocol
            if($ProtocolOK -eq $true){
                Try {
                    New-ItemProperty -Path $ProtocolBaseKey -Name "URL Protocol" -Value "" -PropertyType String -ErrorAction Stop -force
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Creation of default registry value ($($ProtocolBaseKey):URL Protocol) failed"
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
                    $ProtocolOK = $False
                }
            }

            #Set the command value
            if($ProtocolOK -eq $true){
                Try {
                    New-ItemProperty -Path $ProtocolCommandKey -Name "(Default)" -Value $ProtocolActionValue -PropertyType String -force -ErrorAction Stop
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Creation of default registry value ($($ProtocolCommandKey):(Default)) failed"
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError 
                    $ProtocolOK = $False
                }
            }

            if($ProtocolOK -eq $true){
                $ProtocolsProcessed = $ProtocolsProcessed + 1
            }
        }
    }

    if(($FunctionStatus.Status -eq $True) -and ($ProtocolCount -gt 0)) {
        If ($ProtocolsProcessed -eq $ProtocolCount) {
            New-LogEntry -LogEntry "All protocols were processed correctly"
        } else {
            New-LogEntry -LogEntry "Some protocols were not processed correctly"
            $FunctionStatus.Status = $False
        }
    }

    Return $FunctionStatus
}

Function Get-LoggedinUserInfo {

    $UserInfoArray = [PSCustomObject]@{
        "Status" = $true
        "UserName" = ""
        "UserSID" = ""
        "UserRegistry" = ""
        "UserProfile" = ""
    }


    #Grab the logged in user from WMI
    Try {
        $LoggedInUserWMI = Get-WmiObject -class win32_computersystem | seleobject username
    } Catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Error retrieving Logged in User from WMI" -LogLevel $LogLevelError
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
    }
    
    #If the username is not a valid username then error handling is required
    If($null -eq $LoggedInUserWMI.Username) {
        New-LogEntry -LogEntry "No user is currently logged in" -LogLevel $LogLevelWarning
        $UserInfoArray.Status = $False
    } else {
        New-LogEntry -LogEntry "Logged in user account: $($LoggedInUserWMI.Username)"
        If ($LoggedInUserWMI.Username -like "*\*") {
            $LoggedinUser = $LoggedInUserWMI.username.Split("\")
            $UserInfoArray.UserName = $LoggedinUser[1]
            #Get the SID of the User
            $UserInfoArray.UserProfile = "c:\users\" + $LoggedinUser[1]
            $UserInfoArray.UserSID = (Get-WmiObject win32_userprofile | Where-Object localpath -like $UserInfoArray.UserProfile | seleobject SID).SID
            $UserInfoArray.UserRegistry = ("Registry::\HKEY_USERS\" + $UserInfoArray.UserSID)
            New-LogEntry -LogEntry  "Logged in User Registry $($UserInfoArray.UserRegistry)"
        } else {
            New-LogEntry -LogEntry "Logged in user format not recognized" -LogLevel $LogLevelError
            $UserInfoArray.Status = $False
            
        }
    }

    Return $UserInfoArray
}

################################################
# SECTION 1: Script Initialization
################################################

# SECTION 1 STEP 1: Create a Log file
New-LogEntry -LogEntry "SECTION 1 STEP 1: Create a Log file"
$ReturnedLogFile = New-TxtLog -NewlogPath $LogPath -NewLogPrefix $TxtLogfilePrefix
If(($ReturnedLogFile | Measure-Object).count -eq 1) {
    $TxtLogfile = $ReturnedLogFile
    New-LogEntry -LogEntry "Writing Log file to $($TxtLogfile)"
} else {
    Foreach($file in $ReturnedLogFile) {
        #Workaround for the returned value being returned as an array object
        New-LogEntry -LogEntry "Checking that the log file $($file) exists"
        if(test-path -Path $file -PathType Leaf) {
            $TxtLogfile = $file
            New-LogEntry -LogEntry "Writing Log file to $($TxtLogfile)"
        }
    }
}

# SECTION 1 STEP 2: Load the Config.xml
New-LogEntry -LogEntry "SECTION 1 STEP 2: Load the Config.xml"
New-LogEntry -LogEntry "Install folder location: $installFolder"
New-LogEntry -LogEntry "Loading configuration location: $($installFolder)Config.xml"
try {
    [Xml]$config = Get-Content "$($installFolder)Config.xml"
} catch {
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error loading the config XML" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to load the Config XML - Script exiting"
}

# SECTION 1 STEP 3: Get the Marker Name
New-LogEntry -LogEntry "SECTION 1 STEP 2: Get the Marker Name"
if($config.config.Marker.length -eq 0) {
    New-LogEntry -LogEntry "Marker file name not found in the config XML" -LogLevel $LogLevelError 
    Exit-Script -ExitText "Unable to load the marker file name from the Config XML - Script exiting"
} else {
    $MarkerName = $config.config.Marker
}

# SECTION 1 STEP 4: #Obtain the current logged in user
New-LogEntry -LogEntry "Obtaining the logged in user information"
$UserInfo = Get-LoggedinUserInfo
If ($UserInfo.Status -eq $true) {
    $Username = $UserInfo.UserName
    $UserSID = $UserInfo.UserSID
    $UserRegistry = $UserInfo.UserRegistry
    $UserProfile = $UserInfo.UserProfile
    New-LogEntry -LogEntry "Obtained user information for $($Username) - SID $($UserSID)"
} else {
    New-LogEntry -LogEntry "Failed to retrieve the logged in user information" -LogLevel $LogLevelError
    $ProcessToastProtocols = $False
}


################################################
# SECTION 2: Install MSI
################################################
New-LogEntry -LogEntry "### SECTION 2: Installing MSI ###"

#Create the MSI Path
$MSIPath = Join-Path -Path $InstallFolder -ChildPath $config.config.MSI

#Check that the MSI exists
if(Test-Path -Path $MSIPath -PathType Leaf) {
    New-LogEntry -LogEntry "Installing MSI from $($MSIPath)"
} else {
    New-LogEntry -LogEntry "MSI ($($MSIPath)) not found" -LogLevel $LogLevelError 
    Exit-Script -ExitText "MSI not found - Script exiting"
}
$InstallMSIArguments = "/q"
$InstallMSIOK = Install-MSI -MSI $MSIPath -MSIArguments $InstallMSIArguments
If ($InstallMSIOK -eq $true) {
    New-LogEntry -LogEntry "Successfully installed MSI file $($MSIPath)"
} else {
    New-LogEntry -LogEntry "Failed to install MSI file $($MSIPath)"
    Exit-Script -ExitText "MSI not installed - Script exiting"
}


################################################
# SECTION 3: Secure Scripts Folders
################################################

New-LogEntry -LogEntry "### SECTION 3: Secure Scripts Folders ###"

# SECTION 3 STEP 1: Get the Scripts folders
New-LogEntry -LogEntry "*** SECTION 3 Step 1: Initalizing the Scripts folder variables ***"
#Set the process scripts flag
$ProcessScripts = $True

#Get the App folder from the config
If(!($config.Config.AppPath.length -eq 0)) {
    $AppFolder = $config.Config.AppPath
    #Check the the App folder exists
    if(Test-Path -Path $AppFolder -PathType Container) {

    } else {
        New-LogEntry -LogEntry "App Folder path ($($AppFolder)) not found" -LogLevel $LogLevelError
        $ProcessScripts = $False    
    }
} else {
    New-LogEntry -LogEntry "AppFolder path is missing from the config" -LogLevel $LogLevelError
    $ProcessScripts = $False
}

#Set the Secure Scripts folder variable
If(!($config.Config.Scripts.ScriptsSecure.length -eq 0)) {
    $SecureScriptsFolder = join-path -path (Join-Path -Path $AppFolder -ChildPath "Scripts") -ChildPath $config.Config.Scripts.ScriptsSecure
} else {
    $SecureScriptsFolder = join-path -path (Join-Path -Path $AppFolder -ChildPath "Scripts") -ChildPath "Secure"
}

#Set the User Scripts folder variable
If(!($config.Config.Scripts.ScriptsUser.Length -eq 0))  {
    $UserScriptsFolder = join-path -path (Join-Path -Path $AppFolder -ChildPath "Scripts") -ChildPath $config.Config.Scripts.ScriptsUser
} else {
    $UserScriptsFolder = join-path -path (Join-Path -Path $AppFolder -ChildPath "Scripts") -ChildPath "User"
}

#Get the Common folder from the config
If(!($config.Config.CommonPath.length -eq 0)) {
    $CommonFolder = $config.Config.CommonPath
    #Check the the common folder exists
    if(Test-Path -Path $CommonFolder -PathType Container) {

    } else {
        New-LogEntry -LogEntry "Common Folder path ($($CommonFolder)) not found" -LogLevel $LogLevelError
        $ProcessScripts = $False    
    }
} else {
    New-LogEntry -LogEntry "Common Folder path is missing from the config" -LogLevel $LogLevelError
    $ProcessScripts = $False
}

If(!($config.Config.Scripts.ScriptsCommonSecure -eq 0))  {
    $CommonSecureScriptsFolder = join-path -path (Join-Path -Path $CommonFolder -ChildPath "Scripts") -ChildPath $config.Config.Scripts.ScriptsCommonSecure
} else {
    $CommonSecureScriptsFolder = join-path -path (Join-Path -Path $CommonFolder -ChildPath "Scripts") -ChildPath "Secure"
}

If(!($config.Config.Scripts.ScriptsCommonUser.Length -eq 0))  {
    $CommonUserScriptsFolder = join-path -path (Join-Path -Path $CommonFolder -ChildPath "Scripts") -ChildPath $config.Config.Scripts.ScriptsCommonUser
} else {
    $CommonUserScriptsFolder = join-path -path (Join-Path -Path $CommonFolder -ChildPath "Scripts") -ChildPath "User"
}

#Check the Secure Scripts folder exists
If(Test-path -Path $SecureScriptsFolder) {
    New-LogEntry -LogEntry "Secure Scripts folder ($($SecureScriptsFolder)) exists"
} else {
    New-LogEntry -LogEntry "Secure Scripts folder ($($SecureScriptsFolder)) does not exist" -LogLevel $LogLevelError
    $ProcessScripts = $False
}

#Check the User Scripts folder exists
If(Test-path -Path $UserScriptsFolder) {
    New-LogEntry -LogEntry "User Scripts folder ($($UserScriptsFolder)) exists"
} else {
    New-LogEntry -LogEntry "User Scripts folder ($($UserScriptsFolder)) does not exist" -LogLevel $LogLevelError
    $ProcessScripts = $False
}

#Check the Common Secure Scripts folder exists
If(Test-path -Path $CommonSecureScriptsFolder) {
    New-LogEntry -LogEntry "Common Secure Scripts folder ($($CommonSecureScriptsFolder)) exists"
} else {
    New-LogEntry -LogEntry "Common Secure Scripts folder ($($CommonSecureScriptsFolder)) does not exist" -LogLevel $LogLevelError
    $ProcessScripts = $False
}

#Check the Common User Scripts folder exists
If(Test-path -Path $CommonUserScriptsFolder) {
    New-LogEntry -LogEntry "Common User Scripts folder ($($CommonUserScriptsFolder)) exists"
} else {
    New-LogEntry -LogEntry "Common User Scripts folder ($($CommonUserScriptsFolder)) does not exist" -LogLevel $LogLevelError
    $ProcessScripts = $False
}


# SECTION 3 STEP 2: Apply security to the Secure and User Scripts folders
If ($ProcessScripts -eq $True) {
    New-LogEntry -LogEntry "*** SECTION 3 Step 2: Securing the Scripts Folders ***"
    #Create security principal objects
    $SecurityPrincipalBuiltinUsers = new-object System.Security.Principal.NTAccount("BUILTIN\Users")
    $SecurityPrincipalAuthenticatedUser = new-object System.Security.Principal.NTAccount("NT AUTHORITY\Authenticated Users")

    #Get the ACL of the Secure scripts folder
    New-LogEntry -LogEntry "Obtaining the Secure scripts folder ACL"
    $SecureScriptsFolderACL = Get-Acl -Path $SecureScriptsFolder
    #remove inheritance on the ACL
    New-LogEntry -LogEntry "Removing permission inheritance from the ACL"
    $SecureScriptsFolderACL.SetAccessRuleProtection($True,$True)
    #Set the ACL back on the folder
    New-LogEntry -LogEntry "Applying the ACL without inheritance on the Secure scripts folder"
    Set-Acl -Path $SecureScriptsFolder -AclObject $SecureScriptsFolderACL
    #Get the ACL again
    New-LogEntry -LogEntry "Obtaining the Secure scripts folder ACL again"
    $SecureScriptsFolderACL = Get-Acl -Path $SecureScriptsFolder
    #Remove the builtin\users and Authenticated users from the folder
    New-LogEntry -LogEntry "Removing standard user permissions from the ACL"
    $SecureScriptsFolderACL.PurgeAccessRules($SecurityPrincipalBuiltinUsers)
    $SecureScriptsFolderACL.PurgeAccessRules($SecurityPrincipalAuthenticatedUser)
    #Set the ACL on the folder
    New-LogEntry -LogEntry "Applying the ACL without standard user permissions on the Secure scripts folder"
    Set-Acl -Path $SecureScriptsFolder -AclObject $SecureScriptsFolderACL

    #Get the ACL of the User scripts folder
    New-LogEntry -LogEntry "Obtaining the User scripts folder ACL"
    $UserScriptsFolderACL = Get-Acl -Path $UserScriptsFolder
    #remove inheritance on the ACL
    New-LogEntry -LogEntry "Removing permission inheritance from the ACL"
    $UserScriptsFolderACL.SetAccessRuleProtection($True,$True)
    #Set the ACL back on the folder
    New-LogEntry -LogEntry "Applying the ACL without inheritance on the User scripts folder"
    Set-Acl -Path $UserScriptsFolder -AclObject $UserScriptsFolderACL
    #Get the ACL again
    New-LogEntry -LogEntry "Obtaining the User scripts folder ACL again"
    $UserScriptsFolderACL = Get-Acl -Path $UserScriptsFolder
    #Remove the builtin\users and Authenticated users from the folder
    New-LogEntry -LogEntry "Removing standard user permissions from the ACL"
    $UserScriptsFolderACL.PurgeAccessRules($SecurityPrincipalBuiltinUsers)
    $UserScriptsFolderACL.PurgeAccessRules($SecurityPrincipalAuthenticatedUser)
    #Set the ACL on the folder
    New-LogEntry -LogEntry "Applying the ACL without standard user permissions on the User scripts folder"
    Set-Acl -Path $UserScriptsFolder -AclObject $UserScriptsFolderACL
  
    #Get the ACL again
    New-LogEntry -LogEntry "Obtaining the User scripts folder ACL again"
    $UserScriptsFolderACL = Get-Acl -Path $UserScriptsFolder

    #Add the builtin\users and the authenticated users as read
    $BuiltInUserAcessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipalBuiltinUsers,"ReadAndExecute","ContainerInherit,ObjectInherit", "None","Allow")
    $AuthenticatedUserAcessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipalAuthenticatedUser,"ReadAndExecute","ContainerInherit,ObjectInherit", "None","Allow")
    $UserScriptsFolderACL.AddAccessRule($BuiltInUserAcessRule)
    $UserScriptsFolderACL.AddAccessRule($AuthenticatedUserAcessRule)
    #Set the ACL on the folder
    New-LogEntry -LogEntry "Applying the ACL without standard user permissions on the User scripts folder"
    Set-Acl -Path $UserScriptsFolder -AclObject $UserScriptsFolderACL


    #Get the ACL of the Common Secure scripts folder
    New-LogEntry -LogEntry "Obtaining the Common Secure scripts folder ACL"
    $CommonSecureScriptsFolderACL = Get-Acl -Path $CommonSecureScriptsFolder
    #remove inheritance on the ACL
    New-LogEntry -LogEntry "Removing permission inheritance from the ACL"
    $CommonSecureScriptsFolderACL.SetAccessRuleProtection($True,$True)
    #Set the ACL back on the folder
    New-LogEntry -LogEntry "Applying the ACL without inheritance on the Common Secure scripts folder"
    Set-Acl -Path $CommonSecureScriptsFolder -AclObject $CommonSecureScriptsFolderACL
    #Get the ACL again
    New-LogEntry -LogEntry "Obtaining the Common Secure scripts folder ACL again"
    $CommonSecureScriptsFolderACL = Get-Acl -Path $CommonSecureScriptsFolder
    #Remove the builtin\users and Authenticated users from the folder
    New-LogEntry -LogEntry "Removing standard user permissions from the ACL"
    $CommonSecureScriptsFolderACL.PurgeAccessRules($SecurityPrincipalBuiltinUsers)
    $CommonSecureScriptsFolderACL.PurgeAccessRules($SecurityPrincipalAuthenticatedUser)
    #Set the ACL on the folder
    New-LogEntry -LogEntry "Applying the ACL without standard user permissions on the Common Secure scripts folder"
    Set-Acl -Path $CommonSecureScriptsFolder -AclObject $CommonSecureScriptsFolderACL

    #Get the ACL of the Common User scripts folder
    New-LogEntry -LogEntry "Obtaining the Common User scripts folder ACL"
    $CommonUserScriptsFolderACL = Get-Acl -Path $CommonUserScriptsFolder
    #remove inheritance on the ACL
    New-LogEntry -LogEntry "Removing permission inheritance from the ACL"
    $CommonUserScriptsFolderACL.SetAccessRuleProtection($True,$True)
    #Set the ACL back on the folder
    New-LogEntry -LogEntry "Applying the ACL without inheritance on the Common User scripts folder"
    Set-Acl -Path $CommonUserScriptsFolder -AclObject $CommonUserScriptsFolderACL
    #Get the ACL again
    New-LogEntry -LogEntry "Obtaining the Common User scripts folder ACL again"
    $CommonUserScriptsFolderACL = Get-Acl -Path $CommonUserScriptsFolder
    #Remove the builtin\users and Authenticated Common Users from the folder
    New-LogEntry -LogEntry "Removing standard Common User permissions from the ACL"
    $CommonUserScriptsFolderACL.PurgeAccessRules($SecurityPrincipalBuiltinUsers)
    $CommonUserScriptsFolderACL.PurgeAccessRules($SecurityPrincipalAuthenticatedUser)
    #Set the ACL on the folder
    New-LogEntry -LogEntry "Applying the ACL without standard Common User permissions on the Common User scripts folder"
    Set-Acl -Path $CommonUserScriptsFolder -AclObject $CommonUserScriptsFolderACL
  
    #Get the ACL again
    New-LogEntry -LogEntry "Obtaining the Common User scripts folder ACL again"
    $CommonUserScriptsFolderACL = Get-Acl -Path $CommonUserScriptsFolder

    #Add the builtin\users and the authenticated Common Users as read
    $BuiltInUserAcessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipalBuiltinUsers,"ReadAndExecute","ContainerInherit,ObjectInherit", "None","Allow")
    $AuthenticatedUserAcessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipalAuthenticatedUser,"ReadAndExecute","ContainerInherit,ObjectInherit", "None","Allow")
    $CommonUserScriptsFolderACL.AddAccessRule($BuiltInUserAcessRule)
    $CommonUserScriptsFolderACL.AddAccessRule($AuthenticatedUserAcessRule)
    #Set the ACL on the folder
    New-LogEntry -LogEntry "Applying the ACL without standard Common User permissions on the Common User scripts folder"
    Set-Acl -Path $CommonUserScriptsFolder -AclObject $CommonUserScriptsFolderACL

}



################################################
# SECTION 4: Setup Scheduled Tasks
################################################

New-LogEntry -LogEntry "### Section 3: Scheduled Tasks ###"

# SECTION 4 STEP 4: Loop through the Tasks Config and create scheduled tasks
If ($ProcessScripts -eq $True) {
    #Set the PowerShell execution path
    #Force the x64 variant
    If(!([System.Environment]::Is64BitProcess)) {
        New-LogEntry -LogEntry "Script running as "
        $PSpath = "$($PSHOME.ToLower().Replace("syswow64", "system32"))\powershell.exe"
    } else {
        $PSpath = $PSHOME
    }

    $PSpath = Join-Path -Path "C:\Windows\System32\WindowsPowerShell\v1.0" -ChildPath "powershell.exe"
    

    New-LogEntry -LogEntry "*** Step 4: Creating Scheduled Tasks ***"
    ForEach ($Task in $Config.Config.Tasks.Task) {
        New-LogEntry -LogEntry "+++ Processing Task - $($Task.ID) +++"
        
        #Set the process scheduled task flag
        $ProcessScheduledTask = $True
        #Set the replace Scheduled task flag
        $ReplaceScheduledTask = $False #if true at the end of the processing then an existing task will be replaced

        #Set the Task Name
        $TaskName = $Task.TaskName
        New-LogEntry -LogEntry "TaskName: $($TaskName)"

        #If the Task does not already exist then create the task otherwise check whether the task needs to be recreated (I.E. the script has changed)
        if(!(Get-ScheduledTask | where-object {$_.TaskName -eq $TaskName})) {
            $ScheduledTaskExists = $False
            New-LogEntry -logentry "Scheduled Task $($TaskName) does not exist - proceeding to register the scheduled task" 
        } else {
            $ScheduledTaskExists = $True
            $ExistingTask = Get-ScheduledTask | where-object {$_.TaskName -eq $TaskName}
            New-LogEntry -logentry "Scheduled Task $($TaskName) already exists - Checking task" -LogLevel $LogLevelWarning 
        }

        #Construct the path to the task script and confirm the script file exists
        If ($ProcessScheduledTask -eq $true) {
                
            switch -exact ($Task.TaskType) {
                "Secure" {
                    #Set the Task Script path
                    If ($Task.TaskScriptFolder.Length -eq 0){
                        $TaskScript = Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskScript
                    } else {
                        $TaskScript = Join-Path -Path (Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskScript
                    }
                }
                "User" {
                    #Set the Task Script path
                    If ($Task.TaskScriptFolder.Length -eq 0){
                        $TaskScript = Join-Path -Path $UserScriptsFolder -ChildPath $Task.TaskScript 
                    } else {
                        $TaskScript = Join-Path -Path (Join-Path -Path $UserScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskScript
                    }
                }
                "CommonSecure" {
                    #Set the Task Script path
                    If ($Task.TaskScriptFolder.Length -eq 0){
                        $TaskScript = Join-Path -Path $CommonSecureScriptsFolder -ChildPath $Task.TaskScript
                    } else {
                        $TaskScript = Join-Path -Path (Join-Path -Path $CommonSecureScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskScript
                    }
                }
                "CommonUser" {
                    #Set the Task Script path
                    If ($Task.TaskScriptFolder.Length -eq 0){
                        $TaskScript = Join-Path -Path $CommonUserScriptsFolder -ChildPath $Task.TaskScript 
                    } else {
                        $TaskScript = Join-Path -Path (Join-Path -Path $CommonUserScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskScript
                    }
                }
                Default {
                    #Default to the Secure path
                    If ($Task.TaskScriptFolder.Length -eq 0){
                        $TaskScript = Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskScript
                    } else {
                        $TaskScript = Join-Path -Path (Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskScript
                    }
                }
            }    

            #Check that the Scheduled task script exists
            If (Test-Path -Path $TaskScript -PathType Leaf) {
                New-LogEntry -LogEntry "Task Script: $($TaskScript)"
            } else {
                $ProcessScheduledTask = $False
                New-LogEntry -LogEntry "Task Script ($($TaskScript)) not found" -LogLevel $LogLevelError
            }
        }

        
        #Determine whether this is a PowerShell or wscript action
        If(!($Task.TaskExecutable.Length -eq 0)) {
            switch ($Task.TaskExecutable) {
                "powershell" {
                    $TaskExecutableType = $TaskExecutableType_PowerShell
                }
                "wscript" {
                    $TaskExecutableType = $TaskExecutableType_WScript
                }
                Default {
                    $ProcessScheduledTask = $False
                    New-LogEntry -LogEntry "Task Excutable Type ($($Task.TaskExecutable)) was unknown" -LogLevel $LogLevelError
                }
            }
        } else {
            #Default to PowerShell
            $TaskExecutableType = $TaskExecutableType_PowerShell
        }

        #Create the arguments for the PowerShell Task action
        If ($ProcessScheduledTask -eq $true) {
            If($TaskExecutableType -eq $TaskExecutableType_PowerShell) {
                #Set the Task Argument String
                $TaskArgument = '-WindowStyle Hidden -NonInteractive -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "' + $TaskScript + '"'
                    
                #Add the Task Config file if it exists
                If (!($Task.TaskConfig.Length -eq 0)) {
                    If ($Task.TaskScriptFolder.Length -eq 0){
                        switch -exact ($Task.TaskType) {
                            "Secure" {
                                $TaskConfigPath = Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskConfig
                            }
                            "User" {
                                $TaskConfigPath = Join-Path -Path $UserScriptsFolder -ChildPath $Task.TaskConfig
                            }
                            "CommonSecure" {
                                $TaskConfigPath = Join-Path -Path $CommonSecureScriptsFolder -ChildPath $Task.TaskConfig
                            }
                            "CommonUser" {
                                $TaskConfigPath = Join-Path -Path $CommonUserScriptsFolder -ChildPath $Task.TaskConfig
                            }
                            Default {
                                #Default to the Secure path
                                $TaskConfigPath = Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskConfig
                            }
                        }
                    } else {
                        switch -exact ($Task.TaskType) {
                            "Secure" {
                                $TaskConfigPath = Join-Path -Path (Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskConfig
                            }
                            "User" {
                                $TaskConfigPath = Join-Path -Path (Join-Path -Path $UserScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskConfig
                            }
                            "CommonSecure" {
                                $TaskConfigPath = Join-Path -Path (Join-Path -Path $CommonSecureScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskConfig
                            }
                            "CommonUser" {
                                $TaskConfigPath = Join-Path -Path (Join-Path -Path $CommonUserScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskConfig
                            }
                            Default {
                                #Default to the Secure path
                                $TaskConfigPath = Join-Path -Path (Join-Path -Path $SecureScriptsFolder -ChildPath $Task.TaskScriptFolder) -ChildPath $Task.TaskConfig
                            }
                        }
                    }
                    New-LogEntry -LogEntry "Task config: $($TaskConfigPath)" 
                    $TaskArgument = $TaskArgument + ' -Config "' + $TaskConfigPath + '"'
                }
                #Add other task arguments
                If (!($Task.TaskArgument.Length -eq 0)) {
                    $TaskArgument = $TaskArgument + " " + $Task.TaskArgument
                }
            } elseif ($TaskExecutableType = $TaskExecutableType_WScript) {
                $TaskArgument = '"' + $TaskScript + '"'
            }
        }

        #Check whether the current task argument matches the current arguments
        If ($ProcessScheduledTask -eq $true) {
            
            New-LogEntry -LogEntry "Task Argument String: $($TaskArgument)"
            If($ScheduledTaskExists -eq $true) {
                #Check whether the task action argument matches the required task
                New-LogEntry -logentry "Checking the arguments for the existing task $($ExistingTask.TaskName)"
                $ActionArguments = $false
                $ActionExecute = $false
                #Note this assumes that there is only one action but because the returned value is an array, all the actions need to be checked.
                Foreach ($Action in $ExistingTask.Actions) {
                    New-LogEntry -logentry "Exsting argument $($Action.Arguments)"
                    New-LogEntry -logentry "New Argument $($TaskArgument)"
                    #compare the arguments
                    If ($Action.Arguments.tolower() -eq $TaskArgument.ToLower()) {
                        $ActionArguments = $True
                        New-LogEntry -logentry "Match found for existing arguments"
                    }
                    New-LogEntry -logentry "Exsting executed process $($Action.Execute)"
                    If($TaskExecutableType -eq $TaskExecutableType_PowerShell) {
                        New-LogEntry -logentry "New executed process $($PSpath)"
                        #Compare the executed process
                        If ($Action.Execute.tolower() -eq $PSpath.ToLower()) {
                            $ActionExecute = $True
                            New-LogEntry -logentry "Match found for existing execution"
                        }
                    } elseif ($TaskExecutableType = $TaskExecutableType_WScript) {
                        New-LogEntry -logentry "New executed process $($WScriptpath)"
                        #Compare the executed process
                        If ($Action.Execute.tolower() -eq $WScriptpath.ToLower()) {
                            $ActionExecute = $True
                            New-LogEntry -logentry "Match found for existing execution"
                        }
                    }
                }
                If (($ActionArguments -eq $false) -or ($ActionExecute -eq $false)) {
                    $ReplaceScheduledTask = $True
                    New-LogEntry -logentry "Arguments for Task $($ExistingTask.TaskName) have changed - task must be re-registered" -LogLevel $LogLevelWarning
                } else {
                    New-LogEntry -logentry "Arguments for Task $($ExistingTask.TaskName) have not changed - task does not need to be re-registered"
                }

            }
        }

        If ($ProcessScheduledTask -eq $true) {
            If($TaskExecutableType -eq $TaskExecutableType_PowerShell) {
                #Set the Task Action - This action requires a try catch block because it can fail
                New-LogEntry -LogEntry "Creating Scheduled Task Action Object for a PowerShell action"            
                try {
                    $TaskAction = New-ScheduledTaskAction -execute $PSpath -Argument $TaskArgument
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Action Object" -LogLevel $LogLevelError
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                    $ProcessScheduledTask = $False
                }
            } elseif ($TaskExecutableType = $TaskExecutableType_WScript) {
                #Set the Task Action - This action requires a try catch block because it can fail
                New-LogEntry -LogEntry "Creating Scheduled Task Action Object for a WScript Action"            
                try {
                    $TaskAction = New-ScheduledTaskAction -execute $WScriptpath -Argument $TaskArgument
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Action Object" -LogLevel $LogLevelError
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                    $ProcessScheduledTask = $False
                }
            }
        }

        If ($ProcessScheduledTask -eq $true) {
            #Set the Task triggers
            New-LogEntry -LogEntry "Creating Task Trigger Array"
            #Create the task trigger array
            $TaskTriggerArray = New-Object System.Collections.ArrayList
            ForEach ($Run in $Task.TaskRun.Run) {
                switch ($Run.RunType) {
                    "Daily" {
                        #Create the task trigger
                        New-LogEntry -LogEntry "Creating Task Trigger: Daily at $($Run.RunTime)"   
                        Try {
                            $TaskTrigger = New-ScheduledTaskTrigger -Daily -At "$($Run.RunTime)" -DaysInterval 1
                        } catch {
                            $ErrorMessage = $_.Exception.Message
                            New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Trigger" -LogLevel $LogLevelError
                            New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                            $ProcessScheduledTask = $False
                            Break
                        }
                        $TaskTriggerArray.Add($TaskTrigger) | out-null
                    }
                    "Weekly" {
                        New-LogEntry -LogEntry "Creating Task Trigger: Weekly on $($Run.RunDay) at $($Run.RunTime)"    
                        Try {
                            $TaskTrigger = New-ScheduledTaskTrigger -Weekly -At "$($Run.RunTime)" -WeeksInterval 1 -DaysOfWeek $Run.RunDay
                        } catch {
                            $ErrorMessage = $_.Exception.Message
                            New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Trigger" -LogLevel $LogLevelError
                            New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                            $ProcessScheduledTask = $False
                            Break
                        }
                        $TaskTriggerArray.Add($TaskTrigger) | out-null

                    }
                    "AtLogon" {
                        New-LogEntry -LogEntry "Creating Task Trigger: At Logon" 
                        Try {
                            $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
                        } catch {
                            $ErrorMessage = $_.Exception.Message
                            New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Trigger" -LogLevel $LogLevelError
                            New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                            $ProcessScheduledTask = $False
                            Break
                        }
                        $TaskTriggerArray.Add($TaskTrigger) | out-null
                    }
                    "None"{
                        New-LogEntry -LogEntry "The run type is set to none - do not create a task schedule item"
                        $TaskTriggerExists = $True
                    }
                    Default {
                        #Default to Once in ten minutes
                        New-LogEntry -LogEntry "Task run Type ($($Run.RunType)) is unknown" -LogLevel $LogLevelWarning
                        New-LogEntry -LogEntry "Creating Task Trigger: Once"
                        $TaskTriggerExists = $True 
                        Try {
                            $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-date).AddMinutes(10)
                        } catch {
                            $ErrorMessage = $_.Exception.Message
                            New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Trigger" -LogLevel $LogLevelError
                            New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                            $ProcessScheduledTask = $False
                            Break
                        }
                        $TaskTriggerArray.Add($TaskTrigger) | out-null
                    }
                }
                If($TaskTriggerExists -eq $false) {
                    New-LogEntry -LogEntry "The Task Trigger is missing from the existing scheduled task" 
                    $ReplaceScheduledTask = $True
                }
            }

            #confirm the size of the task trigger array
            If ($TaskTriggerArray.count -eq 0) {
                New-LogEntry -LogEntry "No Task triggers were added to the array" -LogLevel $LogLevelWarning
                $CreateWithoutTaskTrigger = $True
                #Work out whether the existing task should be replaced
                If($ExistingTask.Triggers.count -ne 0) {
                    New-LogEntry -LogEntry "The configured task has no triggers but existing task has $($ExistingTask.Triggers.count) triggers - task will be replaced"  -LogLevel $LogLevelWarning
                    $ReplaceScheduledTask = $True
                }
            } else {
                $CreateWithoutTaskTrigger = $false
                #Work out whether the existing task should be replaced
                If($ExistingTask.Triggers.count -eq $TaskTriggerArray.count) {
                    New-LogEntry "Checking that the configured and existing triggers match"
                    #Check the Task Triggers Match the Existing tasks
                    $ExistingTriggers = $ExistingTask.Triggers
                    $MatchTaskTriggers = Find-TaskTriggerMatch -TriggerArray $TaskTriggerArray -Existing $ExistingTriggers
                    If($MatchTaskTriggers -eq $True) {
                        New-LogEntry -LogEntry "The Existing task has the same triggers as the configured triggers"
                    } else {
                        New-LogEntry -LogEntry "The Existing task triggers do not match the configured triggers - task will be replaced"  -LogLevel $LogLevelWarning
                        $ReplaceScheduledTask = $True
                    }
                } else {
                    New-LogEntry -LogEntry "The number of triggers on the existing task ($($ExistingTask.Triggers.count)) does not match the number of configured triggers ($($TaskTriggerArray.count)) - task will be replaced"  -LogLevel $LogLevelWarning
                    $ReplaceScheduledTask = $True
                }
            }
        }

        If ($ProcessScheduledTask -eq $true) {
            Switch -exact ($Task.TaskPrincipal) {
                "System" {
                    #Set the task principal
                    New-LogEntry -LogEntry "Creating Task Principal" 
                    Try {
                        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
                    } catch {
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Principal" -LogLevel $LogLevelError
                        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                        $ProcessScheduledTask = $False
                    }
                }
                "User" {
                    #Set the task principal
                    New-LogEntry -LogEntry "Creating Task Principal" 
                    Try {
                        $TaskPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
                    } catch {
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Principal" -LogLevel $LogLevelError
                        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                        $ProcessScheduledTask = $False
                    }
                }
                default {
                    #Default to System
                    New-LogEntry -LogEntry "Creating Task Principal" 
                    Try {
                        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
                    } catch {
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Principal" -LogLevel $LogLevelError
                        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                        $ProcessScheduledTask = $False
                    }
                }
            }
        }
        
        If ($ProcessScheduledTask -eq $true) {
            #Creating the Task Settings
            New-LogEntry -LogEntry "Creating Task Settings Set" 
            Try {
                $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Setting Set" -LogLevel $LogLevelError
                New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                $ProcessScheduledTask = $False
            }
        }

        #If the task is disabled then re-create the task
        If ($ProcessScheduledTask -eq $true) {
            if($ScheduledTaskExists -eq $True) {
                if((Get-ScheduledTask | where-object {$_.TaskName -eq $TaskName}).State -eq "Disabled") {
                    $ReplaceScheduledTask = $True
                    New-LogEntry -logentry "Scheduled Task $($TaskName) is disabled - proceeding to re-register the scheduled task" -LogLevel $LogLevelWarning
                } else {
                    New-LogEntry -logentry "Scheduled Task $($TaskName) is enabled - Continuing to checking task" 
                }
            }
        }
    
        If ($ProcessScheduledTask -eq $true) {
            #Create the task object
            New-LogEntry -LogEntry "Creating the Scheduled Task object" 
            Try {
                If ($CreateWithoutTaskTrigger -eq $true) {
                    $TaskObject = New-ScheduledTask -Action $TaskAction -Principal $TaskPrincipal -Settings $TaskSettings
                } else {
                    $TaskObject = New-ScheduledTask -Action $TaskAction -Trigger $TaskTriggerArray -Principal $TaskPrincipal -Settings $TaskSettings
                }
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-LogEntry -LogEntry "Error occurred creating a Scheduled Task Object" -LogLevel $LogLevelError
                New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                $ProcessScheduledTask = $False
            }
        }

        If ($ProcessScheduledTask -eq $true) {
            if($ScheduledTaskExists -eq $True){
                If($ReplaceScheduledTask -eq $True) {
                    $RegisterScheduleTask = $True
                    #Remove the existing scheduled task
                    New-LogEntry -logentry "Unregistering the old scheduled task" -LogLevel $LogLevelWarning
                    try {
                        Unregister-ScheduledTask -TaskName $ExistingTask.TaskName -TaskPath $ExistingTask.TaskPath -Confirm:$false
                    } catch {
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Error occurred unregistering an existing Scheduled Task" -LogLevel $LogLevelError
                        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                        $ProcessScheduledTask = $False
                    }
                } else {
                    $RegisterScheduleTask = $false
                    New-LogEntry -logentry "Existing task does not need to be re-registered"
                }
            } else {
                $RegisterScheduleTask = $True
            }
        }

        If ($ProcessScheduledTask -eq $true) {
            If($RegisterScheduleTask -eq $True) {
                #Registering Scheduled Task
                
                New-LogEntry -LogEntry "Registering Scheduled Task $($TaskName)" 
                Try {
                    Register-ScheduledTask $TaskName -InputObject $TaskObject
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Error occurred registering a Scheduled Task" -LogLevel $LogLevelError
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                    $ProcessScheduledTask = $False
                }
            }
        }
        
        If ($ProcessScheduledTask -eq $true) {
            If($Task.StartImmediately.ToLower() -eq "yes") {
                New-LogEntry -LogEntry "Starting $($TaskName) Scheduled Task" 
                Try {
                    Start-ScheduledTask -TaskName $TaskName
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    New-LogEntry -LogEntry "Error occurred starting a Scheduled Task" -LogLevel $LogLevelError
                    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                }
            }
        }
    }
}

################################################
# SECTION 5: Configure Toast Protocols
################################################

New-LogEntry -LogEntry "### Section 5: Configure Toast Protocols ###"

# Section 5 Step 1: Setup toast Protocols
If ($ProcessToastProtocols -eq $true) {
    New-LogEntry -LogEntry "*** Step 1: Configuring Toast Message Protocols ***"
    $configureToastProtocols = Set-ToastProtocols
    If($configureToastProtocols.Status -eq $True) {
        New-LogEntry -LogEntry "The Toast Protocols were successfully configured"
    } else {
        New-LogEntry -LogEntry "The Toast Protocols were not successfully configured" -LogLevel $LogLevelError
        $DisplayToast = $False
    }

}

# Section 5 Step 2: Enable Toast Notifications in Windows
If ($ProcessToastProtocols -eq $true) {
    New-LogEntry -LogEntry "*** Step 2: Fixing Action Centre Toast Notifications ***"
    New-LogEntry -LogEntry "Setting Push Notification Registry key"
    try{
        Set-ItemProperty -Path "$($UserRegistry)\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 1
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Failed to update the push notifications registry key" -LogLevel $LogLevelError
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
        $DisplayToast = $False
    }
}
If ($ProcessToastProtocols -eq $true) {
    # Restart the push notification service
    New-LogEntry -LogEntry "Restarting the Push Notification service"
    try{
        Restart-Service -Name "WpnUserService*"
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Failed to Restart the User Push Notifications service" -LogLevel $LogLevelError
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
        $DisplayToast = $False
    }
    if($DisplayToast -eq $true) {
        #Pause for five seconds to allow the service to restart
        Start-Sleep -seconds 5
    }
}

################################################
# Final SECTION: Script Exit
################################################
New-LogEntry -LogEntry "### Final Section: Cleanup and Exit ###"

#Flush the log cache before exiting
If($DebugScript -eq $true) {
    stop-transcript
}

#Create a marker to indicate the install is complete
$MarkerPath = Join-Path -Path $AppFolder -ChildPath $MarkerName
Set-Content -Path $MarkerPath -Value "Installed $(get-date -Format "dd-MMM-yyyy hh:mm")"

Exit-Script -ExitText "Script complete"
