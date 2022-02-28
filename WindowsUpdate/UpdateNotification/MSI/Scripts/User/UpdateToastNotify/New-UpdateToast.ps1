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
Filename:      New-UpdateToast.ps1
Documentation: https://tothecloudandbeyond.substack.com/
Execution Tested on: Windows 10 2009
Requires:      Setup as a scheduled task
Versions:
1.0 - July 2021 - Intial Release 
 - First release created of the Toast notification system
 - Reads a registry value to determine the action required
1.1 - 21-Dec-2021
 - customised for use as an update notifier
===========================================================================
.SYNOPSIS

Displays Toast Notifications during Autopilot Deployment

.DESCRIPTION
Section 0 - Script initialisation
Section 1 - Load Config
Section 2 - Display Toast if required
Section 3 - Close Out

.INPUTS
The execution engine is controled by a config file (config.xml). Some areas of the script reference additional config files

.OUTPUTS
Outputs a log file in CMTrace format
#>

Param(
	[Parameter(Mandatory=$true)]    
    [string]$ConfigFile
)

################################################
#Declare Constants and other Script Variables
################################################

#Log Levels
[string]$LogLevelError = "Log_Error"
[string]$LogLevelWarning = "Log_Warning"
[string]$LogLevelInfo = "Log_Information"

#[string]$LogPath = "C:\Program Files\Deploy\DeployLog"
#use the $env:TEMP folder as the log location
[string]$LogPath = "$((join-path -path $env:userprofile -childpath "appdata\local\temp\DeployToast"))"
[string]$TxtLogfilePrefix = "UpdateToast" # Log file in cmtrace format

$LogCacheArray = New-Object System.Collections.ArrayList
$MaxLogCachesize = 10
$MaxLogWriteAttempts = 5

#Specify the application used to lauch the Toast nortification against
$ToastLauncherID = "MSEdge"

################################################
#Declare Functions
################################################

<# Create a New log entry in log files #>
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
    Write-Host "$($LogEntry) $($ScriptLineNumber)"
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
}

Function Write-LogEntry {
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
    #Determine the action based on the log level
    switch ($LogLevel) {
        $LogLevelError {  
            #Create the CMTrace Log Line
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 3 + '" thread="" file="">'
        }
        $LogLevelWarning {
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 2 + '" thread="" file="">'
        }
        $LogLevelInfo {
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
        }
        default {
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
        }
    }

    #Write the CMTrace Log line
    Add-Content -Value $TXTLogLine -Path $TxtLogFile -force
}

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
        } Catch {
            $ErrorMessage = $_.Exception.Message
            $WriteLog = $false
            Write-Host "Log entry flush failed"
            Write-Host $ErrorMessage
        }
        If ($WriteLog -eq $false) {
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
    New-Item -Path $NewLogfile -Type File -force | Out-Null

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

<# Get the Toast Action Configuration #>
function Get-ToastConfig {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Type
    )

    #Create a Toast notification configuration object
    $Toast_Config = New-Object -TypeName PSObject -Property @{
        "Status" = $true
        "ToastHello" = ""
        "ToastTitle" = ""
        "Signature" = ""
        "EventTitle" = ""
        "EventText" = ""
        "ButtonTitle" = ""
        "ButtonAction" = ""
        "SnoozeTitle" = ""
        "HeroImage" = ""
        "BadgeImage" = ""
    }

        #Check Required Action against the config
    $Actionfound = $False
    Foreach($ToastAction in $Config.Toast.ToastActions.ToastAction) {
        If($Type.toLower() -eq $ToastAction.ActionID.tolower()) {
            #copy the values to the Toast notification configuration Object
            New-LogEntry -LogEntry "Found Toast Action $($Type) in the configuration. Processing actions"
            $Actionfound = $True
            If(!($ToastAction.ToastHello.length -eq 0)) {
                $Toast_Config.ToastHello = $ToastAction.ToastHello
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Toast Hello configuration was not specified" -LogLevel $LogLevelWarning
            }
        
            If(!($ToastAction.ToastTitle.length -eq 0)) {
                $Toast_Config.ToastTitle = $ToastAction.ToastTitle
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Toast Title configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.Signature.length -eq 0)) {
                $Toast_Config.Signature = $ToastAction.Signature
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Toast Signature configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.EventTitle.length -eq 0)) {
                $Toast_Config.EventTitle = $ToastAction.EventTitle
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Event Title configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.EventText.length -eq 0)) {
                $Toast_Config.EventText = $ToastAction.EventText
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Event Text configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.ButtonTitle.length -eq 0)) {
                $Toast_Config.ButtonTitle = $ToastAction.ButtonTitle
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Button Title configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.ButtonAction.length -eq 0)) {
                $Toast_Config.ButtonAction = $ToastAction.ButtonAction
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Toast Title configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.SnoozeTitle.length -eq 0)) {
                $Toast_Config.SnoozeTitle = $ToastAction.SnoozeTitle
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Toast Title configuration was not specified" -LogLevel $LogLevelWarning
            }

            If(!($ToastAction.HeroImage.length -eq 0)) {
                #Check the image exists
                If(Test-Path -Path $ToastAction.HeroImage -PathType leaf) {
                    New-LogEntry -LogEntry "The hero image file ($($ToastAction.HeroImage)) for Toast Action $($Type) exists"
                    #Convert the file path to a file:/// path
                    $Toast_Config.HeroImage = Convert-FilePath -FilePath $ToastAction.HeroImage
                } else {
                    $Toast_Config.Status = $False
                    New-LogEntry -LogEntry "The hero image file ($($ToastAction.HeroImage)) does not exist" -LogLevel $LogLevelWarning
                }
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The hero image configuration was not specified"
            }
            If(!($ToastAction.BadgeImage.length -eq 0)) {
                #Check the image exists
                If(Test-Path -Path $ToastAction.BadgeImage -PathType leaf) {
                    New-LogEntry -LogEntry "The Badge image file ($($ToastAction.BadgeImage)) for Toast Action $($Type) exists"
                    $Toast_Config.BadgeImage = Convert-FilePath -FilePath $ToastAction.BadgeImage
                } else {
                    $Toast_Config.Status = $False
                    New-LogEntry -LogEntry "The Toast Badge Image file does not exist" -LogLevel $LogLevelWarning
                }
            } else {
                $Toast_Config.Status = $False
                New-LogEntry -LogEntry "The Badge Image configuration was not specified" -LogLevel $LogLevelWarning
            }
        }
    }

    If ($Actionfound -eq $true) {
        New-LogEntry -LogEntry "The Toast Action configuration was found in the config for Toast Action $($Type)"
    } else {
        $Toast_Config.Status = $False
        New-LogEntry -LogEntry "The Toast Action configuration was not found in the config for Toast Action $($Type)" -LogLevel $LogLevelError
        New-LogEntry -LogEntry "The Toast Action configuration was not found in the config"
    }

    If($Toast_Config.Status -eq $false) {
        New-LogEntry -LogEntry "One or more errors occurred loading the config Toast Action $($Type)"
    }
    Return $Toast_Config
}

Function Convert-FilePath {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    [string]$ConvertedPath = "file:///"

    $SplitPath = $FilePath.Split("\")
    Foreach($PathComponent in $SplitPath) {
        If ($ConvertedPath -eq "file:///") {
            $ConvertedPath = $ConvertedPath + $PathComponent
        } else {
            $ConvertedPath = $ConvertedPath + "/" + $PathComponent
        }
    }
    Return $ConvertedPath
}

<# 
    Main routine
#>


################################################
# SECTION 0: Script Initialization
################################################

# SECTION 0 STEP 1: Create a Log file
New-LogEntry -LogEntry "Starting Toast Notification Engine"
New-LogEntry -LogEntry "### Section 0: Script Initialisation ###"
New-LogEntry -LogEntry "*** Step 1: Creating Log File ***"
$TxtLogFile = New-TxtLog -NewlogPath $LogPath -NewLogPrefix $TxtLogfilePrefix


# SECTION 0 STEP 2: Load the Config.xml
New-LogEntry -LogEntry "*** Step 2: Loading config ***"
New-LogEntry -LogEntry "Loading configuration file: $($ConfigFile)"
try {
    [Xml]$config = Get-Content $ConfigFile
} catch {
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error loading the config XML" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to load the Config XML - Script exiting"
}

# SECTION 0 STEP 3: Obtain the current logged in user
New-LogEntry -LogEntry "*** Step 3: Checking Logged In User ***"
#Grab the logged in user from WMI
Try {
    $LoggedInUserWMI = Get-WmiObject -class win32_computersystem | select-object username
   
} Catch {
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error retrieving Logged in User from WMI" -LogLevel $LogLevelError
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
}
New-LogEntry -LogEntry "Logged in user account: $($LoggedInUserWMI.Username)"
#If the username is not a valid username then error handling is required
If($null -eq $LoggedInUserWMI.Username) {
    New-LogEntry -LogEntry "No user is currently logged in" -LogLevel $LogLevelWarning
    Exit-Script -ExitText "No user is currently logged in - Toast notification cannot be sent"
} else {
    If ($LoggedInUserWMI.Username -like "*\*")
    {
        $LoggedinUser = $LoggedInUserWMI.username.Split("\")
        #Get the SID of the User
        $LoggedinUserSID = (Get-WmiObject win32_userprofile | Where-Object localpath -like ("c:\users\" + $LoggedinUser[1]) | select-object SID).SID
        $LoggedinUserRegistry = ("Registry::\HKEY_USERS\" + $LoggedinUserSID)
        New-LogEntry -LogEntry  "Logged in User Registry $($LoggedinUserRegistry)"
    } else {
        New-LogEntry -LogEntry "Logged in user format not recognized" -LogLevel $LogLevelError
        Exit-Script "Error checking logged in user"
    }
}


# SECTION 0 STEP 4: Check Key Elements of the Config.xml
New-LogEntry -LogEntry "*** Step 4: Checking Config ***"

#Retrieve the Toast Registry Key
If(!($Config.Toast.ToastRegistryKey.Length -eq 0))  {
    $ToastRegistryKey = $LoggedinUserRegistry + $Config.Toast.ToastRegistryKey
} else {
    New-LogEntry -LogEntry "The Toast Registry Key is malformed in the config" -LogLevel $LogLevelError
    Exit-Script "Error checking Toast Registry Key in the config"
}

#Retrieve the Toast Action value
If(!($Config.Toast.ToastRegistryAction.Length -eq 0))  {
    $ToastRegistryAction = $Config.Toast.ToastRegistryAction
} else {
    New-LogEntry -LogEntry "The Toast Registry action value is malformed in the config" -LogLevel $LogLevelError
    Exit-Script "Error checking Toast Registry action in the config"
}

#Retrieve the Toast Reboot value
If(!($Config.Toast.ToastRegistryReboot.Length -eq 0))  {
    $ToastRegistryReboot = $Config.Toast.ToastRegistryReboot
} else {
    New-LogEntry -LogEntry "The Toast Registry reboot value is malformed in the config" -LogLevel $LogLevelError
    Exit-Script "Error checking Toast Registry reboot in the config"
}


################################################
# Section 1: Toast Preparation
################################################
New-LogEntry -LogEntry  "### Section 1: Toast Preparation ###"

# Section 1 Step 1: Check the Toast Registry Key

#Look for the presence of the flag registry key
New-LogEntry -LogEntry "*** Step 1: Checking Toast Action ***"
If(!(Test-Path -Path $ToastRegistryKey)) {
    New-LogEntry -LogEntry "Registry Key ($($ToastRegistryKey)) does not exist" -LogLevel $LogLevelError
    Exit-Script "No Toast Action Found"
} else {
    New-LogEntry -LogEntry "Registry Key ($($ToastRegistryKey)) exists"
}

#Load the Toast Action Type registry value for the Toast Notification Action
if(!($null -eq (get-item -Path $ToastRegistryKey).getvalue($ToastRegistryAction))) {
    $ToastActionType = (get-item -Path $ToastRegistryKey).getvalue($ToastRegistryAction)
    New-LogEntry -LogEntry "Retrieved Toast Action - $($ToastActionType)"
} else {
    New-LogEntry -LogEntry "Registry value ($($ToastRegistryAction)) does not exist" -LogLevel $LogLevelError
    Exit-Script "No Toast Action Found"
}

#If the action is reboot then load the Registry Reboot date time
If($ToastActionType -eq "ToastReboot") {

    #Get the Last reboot time
    try {
        [datetime]$LastReboot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Failed to retrieve the last boot time"
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
        Exit-Script "Failed to retrieve the last boot time"
    }

    #Get the registry value for the scheduled reboot
    if(!($null -eq (get-item -Path $ToastRegistryKey).getvalue($ToastRegistryReboot))) {
        $ToastRebootRaw = (get-item -Path $ToastRegistryKey).getvalue($ToastRegistryReboot)
        New-LogEntry -LogEntry "Retrieved Toast Reboot Date - $($ToastRebootRaw)"
        If($ToastRebootRaw -eq "None") {
            #No reboot notification required
            New-LogEntry -LogEntry "Registry entry for Reboot Date set to None - No reboot notifiction required"
            Exit-Script "No reboot notifiction required"
        } else {
            #Convert the date time value
            try {
                $RebootScheduleDate = [Datetime]::ParseExact($ToastRebootRaw,"dd-MMM-yyyy-HH-mm-ss",$null)
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-LogEntry -LogEntry "Unable to convert registry value ($($ToastRebootRaw)) to a date value"
                New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError
                Exit-Script "Toast Reboot value is not a date time value"
            }
            
            #Compare the scheduled date and the last reboot date
            if($LastReboot -gt $RebootScheduleDate) {
                New-LogEntry -LogEntry "The last reboot date ($($LastReboot)) is after the requested date ($($RebootScheduleDate)) - No reboot notification required"
                Exit-Script "No reboot notification required"
            } else {
                New-LogEntry -LogEntry "The last reboot date ($($LastReboot)) is before the requested date ($($RebootScheduleDate)) - Reboot notification required"
            }
            
        }
    } else {
        New-LogEntry -LogEntry "Registry value ($($ToastRegistryAction)) does not exist" -LogLevel $LogLevelError
        Exit-Script "No Toast Reboot value Found"
    }
}

#Get the Toast Notfication configuration
$ToastActionConfig = Get-ToastConfig -Type $ToastActionType
If($ToastActionConfig.Status -eq $True) {
    New-LogEntry -LogEntry "The Toast Action configuration for the specified action ($($ToastActionType)) was retrieved from the configuration"
} else {
    New-LogEntry -LogEntry "The Toast Action configuration for the specified action ($($ToastActionType)) was not found or not configured correctly" -LogLevel $LogLevelError
    New-LogEntry -LogEntry "Errors Found: `r`n $($ToastActionConfig.Error)" -LogLevel $LogLevelError
    Exit-Script "Invalid Toast Action"
}

# Section 1 Step 2: Load required assemblies
New-LogEntry -LogEntry "*** Step 2: Loading Assemblies ***"

#Load Assemblies - may require a try catch
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$ToastDuration = "long"
# Section 1 Step 3: Build XML Toast Templates 
New-LogEntry -LogEntry "*** Step 3: Creating XML Templates ***"

If($ToastActionType -eq "ToastReboot") {
[xml]$ToastNotificationTemplate = @"
<toast duration="$ToastDuration" scenario="reminder">
    <visual>
        <binding template="ToastGeneric">
            <text>$($ToastActionConfig.ToastHello)</text>
            <text>$($ToastActionConfig.ToastTitle)</text>
            <text placement="attribution">$($ToastActionConfig.Signature)</text>
            <image placement="hero" src="$($ToastActionConfig.HeroImage)"/>
            <image placement="appLogoOverride" hint-crop="circle" src="$($ToastActionConfig.BadgeImage)"/>
            <group>
                <subgroup>
                    <text hint-style="title" hint-wrap="true" >$($ToastActionConfig.EventTitle)</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                     <text hint-style="body" hint-wrap="true" >$($ToastActionConfig.EventText)</text>
                </subgroup>
            </group>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:notification.default"/>
    <actions>
        <input id="SnoozeTimer" type="selection" title="Select a Snooze Interval" defaultInput="5">
            <selection id="5" content="5 Minutes"/>
            <selection id="10" content="10 Minutes"/>
            <selection id="15" content="15 Minutes"/>
            <selection id="20" content="20 Minutes"/>
            <selection id="30" content="30 Minutes"/>
        </input>
        <action activationType="system" arguments="snooze" hint-inputId="SnoozeTimer" content="$($ToastActionConfig.SnoozeTitle)" id="test-snooze"/>
        <action arguments="dismiss" content="Dismiss" activationType="system"/>
        <action arguments="$($ToastActionConfig.ButtonAction)" content="$($ToastActionConfig.ButtonTitle)" activationType="protocol" />
    </actions>
</toast>
"@
} else {
[xml]$ToastNotificationTemplate = @"
<toast duration="$ToastDuration" scenario="reminder">
    <visual>
        <binding template="ToastGeneric">
            <text>$($ToastActionConfig.ToastHello)</text>
            <text>$($ToastActionConfig.ToastTitle)</text>
            <text placement="attribution">$($ToastActionConfig.Signature)</text>
            <image placement="hero" src="$($ToastActionConfig.HeroImage)"/>
            <image placement="appLogoOverride" hint-crop="circle" src="$($ToastActionConfig.BadgeImage)"/>
            <group>
                <subgroup>
                    <text hint-style="title" hint-wrap="true" >$($ToastActionConfig.EventTitle)</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                     <text hint-style="body" hint-wrap="true" >$($ToastActionConfig.EventText)</text>
                </subgroup>
            </group>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:notification.default"/>
    <actions>
        <input id="SnoozeTimer" type="selection" title="Select a Snooze Interval" defaultInput="5">
            <selection id="5" content="5 Minutes"/>
            <selection id="10" content="10 Minutes"/>
            <selection id="15" content="15 Minutes"/>
            <selection id="20" content="20 Minutes"/>
            <selection id="30" content="30 Minutes"/>
        </input>
        <action activationType="system" arguments="snooze" hint-inputId="SnoozeTimer" content="$($ToastActionConfig.SnoozeTitle)" id="test-snooze"/>
        <action arguments="$($ToastActionConfig.ButtonAction)" content="$($ToastActionConfig.ButtonTitle)" activationType="protocol" />
        <action arguments="dismiss" content="Dismiss" activationType="system"/>
    </actions>
</toast>
"@
}

#Use for debugging only
#$ToastNotificationTemplate.Save([Console]::Out)
################################################
# Section 2: Toast Notification
################################################

# Section 2 Step 1:Prepare XML
New-LogEntry -LogEntry "*** Step 1: Preparing XML Objects ***"
# Create a new XML object
Try {
$ToastNotificationXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
} catch{
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error creating XML object" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to create Toast XML Objects - Script exiting"
}
Try {
    $ToastNotificationXml.LoadXml($ToastNotificationTemplate.OuterXml)
} catch{
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error loading XML from the toast template" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to create Toast XML Objects - Script exiting"
}

# Section 2 Step 2: Prepare and Create Toast Notification
New-LogEntry -LogEntry "*** Step 2: Generating Toast Notification ***"

Try {
    $ToastNotification = [Windows.UI.Notifications.ToastNotification]::New($ToastNotificationXml)
} catch{
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error creating the toast Notification" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to create the toast Notification - Script exiting"
}

Try {
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($ToastLauncherID).Show($ToastNotification)
} catch{
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error launching the Toast notification" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to launch the Toast notification - Script exiting"
}

# Section 2 Step 3: Remove the registry entries
If($ToastActionType -eq "ToastReboot") {
    New-LogEntry -LogEntry "*** Step 3: Leaving Toast Action Registry Key ***"
} else {
    #Remove the registry entry to prevent the entry from running again
    New-LogEntry -LogEntry "*** Step 3: Removing Toast Action Registry Key ***"
    Try {
        Remove-ItemProperty -Path $ToastRegistryKey -Name $ToastRegistryAction
    } catch{
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogEntry "Error loading XML from the toast template" -LogLevel $LogLevelError 
        New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
        
    }
}


################################################
# Section 3: Exit
################################################
New-LogEntry -LogEntry  "### Section 3: Graceful Exit ###"
Exit-Script -ExitText "script complete"