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
Filename:      Remediate-WindowsUpdate.ps1
Documentation: https://tothecloudandbeyond.substack.com/
Execution Tested on: ProActive Remediation
Requires:      Windows 10 21H1
Purpose: A Pro-Active Remediation Script that fixes issues with Windows Update
Versions:
1.0 - 28 February 2022
 - first public release
===========================================================================

.SYNOPSIS
A Pro-Active Remediation Script that fixes issues with Windows Update

.DESCRIPTION
Process Execution:
Section 0: Setup
Section 1: Check Windows Update
Section 1: Clean-up and exit

.PARAMETER DebugMode
Optional - Enable Debug mode with immediate write to screen of log entries

#>

param (
    [Parameter(Mandatory=$false,HelpMessage="Enable Debug mode")]
    [bool]$DebugMode
)


################################################
#Declare Constants and other Script Variables
################################################
#Create the Output Array - will be converted to a text output at the end of the script
$OutputArray = New-Object System.Collections.ArrayList

#Set the Process flags
$ProcessWindowsUpdate = $True
$ProcessRebootToast = $False
$ProcessInstallTargetedUpdates = $False
$ProcessRemediationCooldown = $False
$ProcessUploadLogs = $false
$ErrorFlag = $False

#Logging Variables
$LogAnalyticsWorkspaceID = "<Enter Workspace ID"
$LogAnalyticsSharedKey = "<Enter the Shared Key"

$Log_Type = "ProActive_WU_Remediate"
$TimeStampField = ""
$ComputerName = ""
$UserName = ""
$Script:OutputEntry = 0

$OutputGUID = New-GUID #Generate an output guid to tie the messages from a particular run together

#If Debug is enabled then messages are logged to screen immediately
if($DebugMode -eq $True) {
    $EnableDebug = $true
} else {
    $EnableDebug = $false
}


#The registry key to store a flag
$RemediationFlagPath = "HKLM:\SOFTWARE\Deploy\ProActiveRemediation"
$RemediationFlag = "WURemediationDate"
$RemediationLevelFlag = "WURemediationLevel"
#Remediation Level 1 - Install targeted updates
#Remediation level 2 - Restart Windows Update Service
#Remediation Level 3 - TBC - Maybe clear the Software Distribution folders

$RemediationLevel = 1 #Default to level 1 remediation
$MaxLoops = 6
$LoopDelay = 30

#Toast Variables
$ToastScheduledTask = "User-Update-ToastNotify"
$ToastRegistryKeySuffix = "\Software\Deploy\UpdateToast"
$ToastRegistryAction = "ToastAction"
$ToastRegistryReboot = "ToastReboot"

################################################
#Declare Functions
################################################

<#
    Create a remediation flag
#>
Function Set-WURemediationStatus {

    $FunctionReturn = New-Object -TypeName PSObject -Property @{
        'Status' = $True
        'Date' = "NA"
    }

    if($FunctionReturn.Status -eq $True) {
        #Check whether the flag path exists
        If(Test-path -Path $RemediationFlagPath) {

        } else {
            #Create the flag path
            Try {
                New-Item -Path $RemediationFlagPath -force -ErrorAction Stop
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message "Creation of Remediation flag path ($($RemediationFlagPath)) failed - $($ErrorMessage)" -type "Error"
                $FunctionReturn.Status = $False
            }
        }
    }

    if($FunctionReturn.Status -eq $True) {
        [string]$RemediationDate = get-date -Format "dd-MMM-yyyy-HH-mm-ss"
        $FunctionReturn.Date = $RemediationDate
        Try {
            New-ItemProperty -Path $RemediationFlagPath -Name $RemediationFlag -Value $RemediationDate -PropertyType String -ErrorAction Stop -force
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-Outputline -Message "Creation of Remediation flag failed - $($ErrorMessage)" -type "Error"
            $FunctionReturn.Status = $False
        }
    }

    Return $FunctionReturn
}

<#
    Add an output array line
#>
Function New-Outputline {

    param (
        [Parameter(Mandatory=$true)]    
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","Warning","Error")]
        [string]$Type
    )
    $Script:OutputEntry = $Script:OutputEntry + 1
    Switch($Type){
        "info" {
            $MessageType = "Info"
        }
        "warning" {
            $MessageType = "Warning"
        }
        "error" {
            $MessageType = "Error"
        }
        default {
            $MessageType = "Info"
        }
    }

    #If Debug is enabled then output the message to the screen
    if($EnableDebug -eq $True) {
        Switch($MessageType) {
            "Error" {
                $DebugText = "$($OutputEntry)) Error: $($Message)"
                $DebugColor = "Red"
            }
            "Warning" {
                $DebugText = "$($OutputEntry)) Warning: $($Message)"
                $DebugColor = "Yellow"
            }
            default {
                $DebugText = "$($OutputEntry)) Info: $($Message)"
                $DebugColor = "White"
            }
        }
        Write-Host $DebugText -ForegroundColor $DebugColor
    }

    $Output = New-Object -TypeName PSObject -Property @{
        'Computer' = $ComputerName
        'LoggedInUser' = $UserName
        'MessageType' = $MessageType
        'Message' = $Message
        'RunID' = $OutputGUID
        'EntryID' = $OutputEntry
    }
    $OutputArray.add($Output) | Out-Null
}

<# Create the authorization signature for Azure Log Analytics #>
Function New-LogAnalyticsSignature {
    param (
        [Parameter(Mandatory=$true)]
        $WorkspaceID,
        [Parameter(Mandatory=$true)]
        $SharedKey,
        [Parameter(Mandatory=$true)]
        $SignatureDate,
        [Parameter(Mandatory=$true)]
        $ContentLength,
        [Parameter(Mandatory=$true)]
        $RESTMethod,
        [Parameter(Mandatory=$true)]
        $ContentType,
        [Parameter(Mandatory=$true)]
        $Resource
    )

    $xHeaders = "x-ms-date:" + $SignatureDate
    $StringToHash = $RESTMethod + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $xHeaders + "`n" + $Resource
    
    $BytesToHash = [Text.Encoding]::UTF8.GetBytes($StringToHash)
    $KeyBytes = [Convert]::FromBase64String($SharedKey)

    $SHA256 = New-Object System.Security.Cryptography.HMACSHA256
    $SHA256.Key = $KeyBytes

    $CalculatedHash = $SHA256.ComputeHash($BytesToHash)
    $EncodedHash = [Convert]::ToBase64String($CalculatedHash)
    $Authorization = 'SharedKey {0}:{1}' -f $WorkspaceID,$EncodedHash
    return $Authorization
}


<# Post Log data to Log Analytics #>
Function New-LogAnalyticsData{
    param (
        [Parameter(Mandatory=$true)]
        [String]$WorkspaceID,
        [Parameter(Mandatory=$true)]
        [String]$SharedKey,
        [Parameter(Mandatory=$true)]
        $LogBody,
        [Parameter(Mandatory=$true)]
        [String]$LogType
    )

    #Create the function response
    $FunctionResponse = New-Object -TypeName PSObject -Property @{
        'Status' = $True
        'Error' = ""
    }

    #Create the signature
    $RESTMethod = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $LogBody.Length
    $Signature = New-LogAnalyticsSignature -WorkspaceID $WorkspaceID -SharedKey $SharedKey -SignatureDate $rfc1123date -ContentLength $contentLength -RESTMethod $RESTMethod -ContentType $contentType -Resource $resource

    #Set the URI for the REST operation
    $uri = "https://" + $WorkspaceID + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    #Set the headers
    $headers = @{
        "Authorization" = $Signature;
        "Log-Type" = $LogType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    try{
        Invoke-RestMethod -Uri $uri -Method $RESTMethod -ContentType $contentType -Headers $headers -Body $LogBody -UseBasicParsing
    } catch {
        $ErrorMessage = $_.Exception.Message
        $FunctionResponse.Status = $False
        $FunctionResponse.Error = $ErrorMessage
        Write-Error "Failed to uploaded logs to Log analytics - $($ErrorMessage)"
    }
   
    return $FunctionResponse

}

<# Invoke a process with wait #>
Function Invoke-Process {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Executable,
        [Parameter(Mandatory=$false)]
        $Arguments,
        [Parameter(Mandatory=$false)]
        [Bool]$NoNewWindow
    )
    $filepath = "`"$Executable`""
    #Set the output files variables
    $stdOutTempFile = "$env:TEMP\$((New-Guid).Guid)"
    $stdErrTempFile = "$env:TEMP\$((New-Guid).Guid)"

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
            }
            "ArrayList" {
                $ProcessParameters.Add("ArgumentList",$Arguments)
            }
            Default {
                New-Outputline -message "Unknown argument type supplied" -Type "Error"
                $ReturnValue.Status = $false
            }
        }
    }
    if($ReturnValue.Status -eq $True){
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
    }

    if($ReturnValue.Status -eq $True){
        #Start the process
        Try {
            $Process = Start-Process @ProcessParameters
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-Outputline -message "Process invoke failed - $($ErrorMessage)" -Type "Error"
            $ReturnValue.Status = $false
        }
    }
    if($ReturnValue.Status -eq $True){
        #Check the contents of the output files
        $ProcessOutput = Get-Content -Path $stdOutTempFile -Raw
        $ProcessError = Get-Content -Path $stdErrTempFile -Raw
        if($Process.ExitCode -eq 0) {
            $ReturnValue.Status = $true
        }elseif ($Process.ExitCode -ne 0) {
            $ReturnValue.Status = $False
            New-Outputline -message "The process invoke failed with exit code $($Process.ExitCode)" -Type "Error"
            $ReturnValue.ExitCode = $Process.ExitCode
            if ($ProcessError) {
                New-Outputline -message $ProcessError -LogLevel $LogLevelWarning 
            }
        } else {
            if ([string]::IsNullOrEmpty($ProcessOutput) -eq $false) {
                New-Outputline -message $ProcessOutput 
            }
        }
    }
    
    #Remove the output files
    #Remove-Item -Path $stdOutTempFile, $stdErrTempFile -Force -ErrorAction Ignore
    Return $ReturnValue
    
}

<# Create a Toast Notification #>
Function New-ToastNotification {
    Param(
        [Parameter(Mandatory=$true)][String]$Type
    )
    $FunctionStatus = $True

    #Check that the scheduled task exists
    if(!(Get-ScheduledTask | where-object {$_.TaskName -eq $ToastScheduledTask})) {
        New-Outputline -message "Scheduled task for the Toast Notification ($($ToastScheduledTask)) does not exist" -Type "Error"
        $FunctionStatus = $True
    }

    #Check that the toast registry key is known
    If($FunctionStatus -eq $True) {
        if($ToastRegistryKey -eq "Unknown") {
            New-Outputline -message "Toast Notification registry key is unknown" -Type "Error"
            $FunctionStatus = $True
        }
    }

    #Check whether the Toast Notification Key Exists
    If($FunctionStatus -eq $True) {
        If(!(Test-Path -Path $ToastRegistryKey)) {
            Try{
                New-Item -Path $ToastRegistryKey -force
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -message "Error creating registry key ($($ToastRegistryKey)) - $($ErrorMessage)" -Type "Error"
                $FunctionStatus = $False
            }
        }
    }

    If($FunctionStatus -eq $True) {
        #Create the Toast Notification Type Registry Value
        Try{
            New-ItemProperty -Path $ToastRegistryKey -Name $ToastRegistryAction -PropertyType String -Value $Type -ErrorAction Stop -force
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-Outputline -message "Error creating registry value ($($ToastRegistryKey):$($ToastRegistryAction)) for Action Type $($Type) - $($ErrorMessage)" -Type "Error"
            $FunctionStatus = $False
        }
    }

    If(($FunctionStatus -eq $True) -and ($Type -eq "ToastReboot")) {
        #Create the Toast Reboot time
        [string]$RebootDate = get-date -Format "dd-MMM-yyyy-HH-mm-ss"
        Try{
            New-ItemProperty -Path $ToastRegistryKey -Name $ToastRegistryReboot -PropertyType String -Value $RebootDate -ErrorAction Stop -force
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-Outputline -message "Error creating registry value ($($ToastRegistryKey):$($ToastRegistryReboot)) - $($ErrorMessage)" -Type "Error"
            $FunctionStatus = $False
        }
    }

    If($FunctionStatus -eq $True) {
        # try to start the scheduled task
        try{
            Start-ScheduledTask -TaskName $ToastScheduledTask
        } catch{
            $ErrorMessage = $_.Exception.Message
            New-Outputline -message "Error starting the Scheduled task for the Toast Notification ($($ToastScheduledTask)) - $($ErrorMessage)" -Type "Error"
            $FunctionStatus = $False
        }
        
    }

    Return $FunctionStatus
}

Function Get-WMIUserData {

    $UserInfoArray = [PSCustomObject]@{
        "Status" = $true
        "UserName" = ""
        "UserSID" = ""
        "UserRegistry" = ""
        "UserProfile" = ""
        "UserFullName" = ""
    }

    #Grab the logged in user from WMI
    Try {
        $LoggedInUserWMI = Get-WmiObject -class win32_computersystem | select-object username
    } Catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline "Error retrieving Logged in User from WMI - $($ErrorMessage)" -type "Error"
        $UserInfoArray.Status = $False
    }
    
    #If the username is not a valid username then error handling is required
    if($UserInfoArray.Status -eq $True) {
        If($null -eq $LoggedInUserWMI.Username) {
            New-Outputline "No user is currently logged in" -type "Error"
            $UserInfoArray.Status = $False
        } else {
            $UserInfoArray.UserFullName = $LoggedInUserWMI.Username
            If ($LoggedInUserWMI.Username -like "*\*") {
                $LoggedinUser = $LoggedInUserWMI.username.Split("\")
                $UserInfoArray.UserName = $LoggedinUser[1]
                #Get the SID of the User
                $UserInfoArray.UserProfile = "c:\users\" + $LoggedinUser[1]
            } else {
                New-Outputline "Logged in user format not recognized" -Type "Error"-type "Error"
                $UserInfoArray.Status = $False
            }
        }
    }

    if($UserInfoArray.Status -eq $True) {
        Try {
            #$UserInfoArray.UserSID = (Get-WmiObject win32_userprofile | Where-Object localpath -like $UserInfoArray.UserProfile | select-object SID).SID
            $UserInfoArray.UserSID = (New-Object -ComObject Microsoft.DiskQuota).TranslateLogonNameToSID($UserInfoArray.UserFullName)
        } Catch {
            $ErrorMessage = $_.Exception.Message
            New-Outputline "Error retrieving Logged in User SID from WMI - $($ErrorMessage)" -type "Error"
            $UserInfoArray.Status = $False
        }
    }

    if($UserInfoArray.Status -eq $True) {
        if(!($UserInfoArray.UserSID.length -eq 0)) {
            $UserInfoArray.UserRegistry = ("Registry::\HKEY_USERS\" + $UserInfoArray.UserSID)
        } else {
            New-Outputline "Error retrieving Logged in User SID from WMI - SID was zero length" -type "Error"
            $UserInfoArray.Status = $False
        }
    }
    Return $UserInfoArray
}

Function Get-WURemediationLevel {

    $FunctionReturn = New-Object -TypeName PSObject -Property @{
        'Status' = $True
        'Level' = 1 #Default to level 1
    }

    if($FunctionReturn.Status -eq $True) {
        #Check whether the flag path exists
        If(Test-path -Path $RemediationFlagPath) {
            #Get the Remediation Level flag
            If($null -eq (Get-Item -Path $RemediationFlagPath).getvalue($RemediationLevelFlag)) {
                #The level does not exist
                New-Outputline -Message "Remediation level flag does not exist" -type "Warning"
                $FunctionReturn.Status = $False
            } else {
                try{
                    [int]$level = (Get-Item -Path $RemediationFlagPath).getvalue($RemediationLevelFlag)
                } catch {
                    New-Outputline -Message "Unable to retrieve the Remediation level flag - $($ErrorMessage)" -type "Warning"
                    $FunctionReturn.Status = $False
                }
                if($FunctionReturn.Status -eq $True) {
                    #check the remediation level
                    switch ($level) {
                        1 { 
                            $FunctionReturn.Level = 1
                        }
                        2 { 
                            $FunctionReturn.Level = 2
                        }
                        Default {
                            New-Outputline -Message "Remediation flag Level ($($level)) is unknown" -type "Warning"
                            $FunctionReturn.Status = $False
                        }
                    }
                }
            }
        } else {
            New-Outputline -Message "Remediation flag path ($($RemediationFlagPath)) does not exist" -type "Warning"
            $FunctionReturn.Status = $False
        }
    }

    Return $FunctionReturn
}


################################################
#Section 0 - Setup
################################################

#Section 0 Step 1: Grab the logged in user from WMI

$GetUserDataOK = Get-WMIUserData
if($GetUserDataOK.status -eq $true) {
    $Username = $GetUserDataOK.Username
    $UserRegistry = $GetUserDataOK.UserRegistry
    $ToastRegistryKey = $UserRegistry + $ToastRegistryKeySuffix
} else {
    New-Outputline -Message "Error retrieving WMI User Data" -type "Error"
    $Username = "Unknown"
    $UserRegistry = "Unknown"
    $ToastRegistryKey = "Unknown"
    $ErrorFlag = $True
}

#Section 0 Step 2: Grab the computername from WMI
Try {
    $ComputerName = (Get-WmiObject -class win32_computersystem | select-object Name).Name
} Catch {
    $ErrorMessage = $_.Exception.Message
    New-Outputline -Message "Error retrieving WMI query: $($ErrorMessage)" -type "Error"
    $ErrorFlag = $True
    $ComputerName = "Unknown"
}

#Section 0 Step 3: Get the Remediation level from the registry
$RetrieveRemediationLevel = Get-WURemediationLevel
if($RetrieveRemediationLevel.Status -eq $True) {
    $RemediationLevel = $RetrieveRemediationLevel.Level
    New-Outputline -Message "Running Remediation Level $($RemediationLevel)"
} else {
    $RemediationLevel = 1
    New-Outputline -Message "Unable to retrieve Remeditiation Level - Defaulting to Level 1" -type "Error"
    $ErrorFlag = $True
}

################################################
#Section 1 - Fix Windows Update
################################################

#Section 1 Step 1: Check whether a reboot is pending
If($ProcessWindowsUpdate -eq $true){
    #Get the reboot status
    Try{
        $WURebootStatus = New-Object -ComObject Microsoft.Update.SystemInfo
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to retrieve the Windows Update reboot status - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
    }   
}

If($ProcessWindowsUpdate -eq $true){
    if(!($null -eq $WURebootStatus.RebootRequired)) {
        if($WURebootStatus.RebootRequired -eq $True)  {
            New-Outputline -Message "A reboot to install Windows Updates is pending"
            $ProcessRebootToast = $True
            #Do not process any further fixes
            $ProcessWindowsUpdate = $False
            #Set the remediation cooldown
            $ProcessRemediationCooldown = $True
        } else{
            New-Outputline -Message "A reboot to install Windows Updates is not required yet"
        }
    } else {
        New-Outputline -Message  "Failed to query Windows Update reboot status - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #continue processing to see whether further work can be done
    }
}

#Section 1 Step 2: Check the Windows Update Service and start the serice if necessary
if ($ProcessWindowsUpdate -eq $True) {
    $ExitServiceStartLoop = $False
    $WUServiceLoopCount = 0
    $WUServiceAction = "None"
    #Multi-value flag that determines the nex action
    #None - Start of the process
    #Stop - Stop the WU service with a normal stop
    #ForceStop - Force the WU service to stop by killing the process
    #Start - Start the service
    #WaitStop - wait for the service to stop
    #WaitStart - wait for the service to start
    #Complete - the work is complete

    Do {
        $WUServiceLoopCount = $WUServiceLoopCount + 1
        $LoopStatus = $True

        #Check the service state
        if($LoopStatus -eq $True) {
            try {
                $WUServiceStatus = (Get-Service -Name wuauserv).status
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message "Failed to query Windows Update service - $($ErrorMessage)" -Type "Error"
                $LoopStatus = $False
            }
        }
        if($LoopStatus -eq $True) {
            if($null -eq $WUServiceStatus) {
                New-Outputline -Message "Windows Update service status was null" -Type "Error"
                $LoopStatus = $False
            }
        }

        if($LoopStatus -eq $True) {
            #Determine the next action 
            New-Outputline -Message "Windows Update service State: $($WUServiceStatus)"
            switch ($WUServiceStatus) {
                "Running" {
                    #Determine the next action based on the WUServiceAction
                    Switch ($WUServiceAction) {
                        "None" {
                            If($RemediationLevel -eq 2) {
                                #Set the service action to stop the service
                                $WUServiceAction = "Stop"
                            } else {
                                #The service is running - continue processing the rest of the remediation
                                $WUServiceAction = "Complete"
                            }
                        }
                        "WaitStop" {
                            #Set the service action to force stop the service
                            $WUServiceAction = "ForceStop"
                        }
                        "Stop" {
                            #Set the service action to wait for the service to stop
                            $WUServiceAction = "WaitStop"
                        }
                        "ForceStop" {
                            #Service did not respond to the stop
                            New-Outputline -Message "Windows Update service did not respond to a Force Stop"
                            $LoopStatus = $False
                        }
                        "Start" {
                            #The service is running - continue processing the rest of the remediation
                            $WUServiceAction = "Complete"
                        }
                        "WaitStart" {
                            #The service is running - continue processing the rest of the remediation
                            $WUServiceAction = "Complete"
                        }
                        "Complete" {
                            #Should not occur 
                        }
                        default {
                            #Unknown action type
                            $LoopStatus = $False
                        }
                    }
                }
                "StopPending" {
                    #Determine the next action based on the WUServiceAction
                    Switch ($WUServiceAction) {
                        "None" {
                            #Set the service action to force stop the service
                            $WUServiceAction = "ForceStop"
                        }
                        "Stop" {
                            #Set the service action to force stop the service
                            $WUServiceAction = "ForceStop"
                        }
                        "ForceStop" {
                            #Service did not respond to the stop
                            New-Outputline -Message "Windows Update service did not respond to a Force Stop"
                            $LoopStatus = $False
                        }
                        "Start" {
                            #Set the service action to force stop the service
                            $WUServiceAction = "ForceStop"
                        }
                        "Complete" {
                            #Should not occur 
                        }
                        default {
                            #Unknown action type
                            $LoopStatus = $False
                        }
                    }

                }
                "StartPending" {
                    #Determine the next action based on the WUServiceAction
                    Switch ($WUServiceAction) {
                        "None" {
                            If($RemediationLevel -eq 2) {
                                #Set the service action to stop the service
                                $WUServiceAction = "Stop"
                            } else {
                                #The service is running - continue processing the rest of the remediation
                                $WUServiceAction = "Complete"
                            }
                        }
                        "Stop" {
                            #Set the service action to force stop the service
                            $WUServiceAction = "ForceStop"
                        }
                        "ForceStop" {
                            #Service did not respond to the stop
                            New-Outputline -Message "Windows Update service did not respond to a Force Stop"
                            $LoopStatus = $False
                        }
                        "Start" {
                            #Set the service action to wait for the service to start
                            $WUServiceAction = "WaitStart"
                        }
                        "Complete" {
                            #Should not occur 
                        }
                        default {
                            #Unknown action type
                            $LoopStatus = $False
                        }
                    }

                }
                "Stopped" {
                    #Determine the next action based on the WUServiceAction
                    Switch ($WUServiceAction) {
                        "None" {
                            #Set the service action to start the service
                            $WUServiceAction = "Start"
                        }
                        "Stop" {
                            #Set the service action to start the service
                            $WUServiceAction = "Start"
                        }
                        "ForceStop" {
                            #Set the service action to start the service
                            $WUServiceAction = "Start"
                        }
                        "Start" {
                            #Attempt to start the service again
                            $WUServiceAction = "Start"
                        }
                        "Complete" {
                            #Should not occur 
                        }
                        default {
                            #Unknown action type
                            $LoopStatus = $False
                        }
                    }

                }
                Default {
                    #Unknown action type
                    $LoopStatus = $False
                }
            }
        }

        if(($LoopStatus -eq $True) -and ($WUServiceAction -eq "Stop")) {
            #Stop the service if the action is to stop the service
            New-Outputline -Message "Stopping the Windows Update Service"
            try{
                Stop-Service -Name wuauserv
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message "Failed to stop Windows Update Service - $($ErrorMessage)" -Type "Error"
                $LoopStatus = $False
            }
        }

        if(($LoopStatus -eq $True) -and ($WUServiceAction -eq "ForceStop")) {
            #Get the PID of the service
            try {
                $WUServiceWMI = Get-WmiObject -Class win32_service -Filter "name= 'wuauserv'"
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message "Failed to Get Windows Update Service from WMI - $($ErrorMessage)" -Type "Error"
                $LoopStatus = $False
            }
        }

        if(($LoopStatus -eq $True) -and ($WUServiceAction -eq "ForceStop")) {
            #Force Stop the service if the action is to Force stop the service
            New-Outputline -Message "Force Stopping the Windows Update Service"
            try {
                Stop-Process -Id $WUServiceWMI.processid -Force -PassThru -ErrorAction Stop
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message "Failed to Get Windows Update Service from WMI - $($ErrorMessage)" -Type "Error"
                $LoopStatus = $False
            }
        }

        if(($LoopStatus -eq $True) -and ($WUServiceAction -eq "Start")) {
            #Start the service if required
            New-Outputline -Message "Starting the Windows Update Service"
            try{
                Start-Service -Name wuauserv
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message "Failed to start Windows Update Service - $($ErrorMessage)" -Type "Error"
                $LoopStatus = $False
            }
        }

        

        if($LoopStatus -eq $True){
            if($WUServiceAction -eq "Complete") {
                New-Outputline -Message "Windows Update Service ready to continue processing"
                #Exit the loop
                $ExitServiceStartLoop = $True
            } else {
                if($WUServiceLoopCount -eq $MaxLoops) {
                    New-Outputline -Message "Loop threshold exceeded - Windows Update Service is not ready for processing"
                    #Exit the loop
                    $ExitServiceStartLoop = $True
                    #Set the error flag so that an error status is added to the log
                    $ErrorFlag = $True
                    #Stop further processing
                    $ProcessWindowsUpdate = $False
                } else {
                    #Pause for a delay
                    New-Outputline -Message "Waiting for service actions to complete before trying again"
                    Start-Sleep -Seconds $LoopDelay
                }
            }
        } else {
            if($WUServiceLoopCount -eq $MaxLoops) {
                New-Outputline -Message "Loop threshold exceeded - Windows Update Service is not ready for processing"
                #Exit the loop
                $ExitServiceStartLoop = $True
                #Set the error flag so that an error status is added to the log
                $ErrorFlag = $True
                #Stop further processing
                $ProcessWindowsUpdate = $False
            } else {
                #Pause for a delay
                New-Outputline -Message "The last loop action failed - Waiting before trying again"
                Start-Sleep -Seconds $LoopDelay
            }
        }
    } until($ExitServiceStartLoop -eq $true)
}

#Section 1 Step 3:  Start Windows Update Detection

if ($ProcessWindowsUpdate -eq $True) {
    #Run the usoclient
    $RunUSO = Invoke-Process -Executable "C:\windows\system32\UsoClient.exe" -Arguments "startscan"
    if($RunUSO.Status -eq $True) {
        New-Outputline -Message "Windows Update Detection Started"
    } else {
        New-Outputline -Message "Windows Update Detection did not start"
    }
    #Pause for thirty seconds to let the process run
    Start-Sleep -Seconds 30
}

#Section 1 Step 4:  Identify Updates for Targeted installation

If($ProcessWindowsUpdate -eq $true){
    #Create a Windows Update session object
    Try{
        $WUSession = New-Object -ComObject Microsoft.Update.Session
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update service session object from COM - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessWindowsUpdate = $False
    }   
}

If($ProcessWindowsUpdate -eq $true){
    #Create a Windows Update Searcher object
    Try{
        $WUSearcher = $WUSession.CreateUpdateSearcher()
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update Searcher object - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessWindowsUpdate = $False
    }   
}

If($ProcessWindowsUpdate -eq $true){
    #search for the available updates
    Try{
        $AvailableUpdatesList = ($WUSearcher.Search("IsInstalled=0 and IsHidden=0")).Updates
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to search for available windows Updates - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessWindowsUpdate = $False
    }   
}

If($ProcessWindowsUpdate -eq $true){
    $AvailableUpdates = 0
    $UpdatesTargetedforInstall = 0
    $TargetedUpdates = New-Object -ComObject "Microsoft.Update.UpdateColl"
    foreach($AvailableUpdate in $AvailableUpdatesList){
        $InstallUpdate = $False
        if($AvailableUpdate.Deploymentaction -eq 1) {
            $AvailableUpdates = $AvailableUpdates +1
            #Determine whether the available update is a cumulative update
            if($AvailableUpdate.Title.Contains("Cumulative Update for Windows") -eq $True) {
                $InstallUpdate = $True
            } 
            #Determine whether the update is KB4023057
            if($AvailableUpdate.Title.Contains("KB4023057") -eq $True) {
                $InstallUpdate = $True
            } 
        }
        
        if($InstallUpdate -eq $True) {
            #Add the update to the update installation array
            $UpdatesTargetedforInstall = $UpdatesTargetedforInstall + 1
            $TargetedUpdates.add($AvailableUpdate)
            New-Outputline -Message "Added $($AvailableUpdate.Title) to the targeted update list"
        }
    }
    if($UpdatesTargetedforInstall -eq 0) {
        New-Outputline -Message "No targeted updates found"
        $ProcessRemediationCooldown = $True
    } else {
        $ProcessInstallTargetedUpdates = $True
        if($UpdatesTargetedforInstall -eq 1) {
            New-Outputline -Message "Found $($UpdatesTargetedforInstall) update that is available for deployment"
        } else{
            New-Outputline -Message "Found $($UpdatesTargetedforInstall) updates that are available for deployment"
        }  
    }
}

#Section 1 Step 5: Download Targeted updates
if($ProcessInstallTargetedUpdates -eq $True) {
    #Create a Windows Update downloader object
    Try{
        $WUDownloader = $WUSession.CreateUpdateDownloader() 
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update Downloader object - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    } 
}

if($ProcessInstallTargetedUpdates -eq $True) {
    Try{
        $WUDownloader.Updates = $TargetedUpdates
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to set the update collection on the Windows Update Downloader object - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    } 
}

if($ProcessInstallTargetedUpdates -eq $True) {
    New-Outputline -Message "Starting Targeted Update Download"
    Try{
        $WUDownload = $WUDownloader.Download()
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to start the Windows Update Downloads - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    } 
}

if($ProcessInstallTargetedUpdates -eq $True) {
    if($WUDownload.ResultCode -eq 2) {
        New-Outputline -Message "Windows Update Download Succeeded"
    } else {
        New-Outputline -Message "Windows Update Download Result Code: $($WUDownload.ResultCode)"
    }
}

if($ProcessInstallTargetedUpdates -eq $True) {
    #Check the Update Search to confirm that the updates are downloaded
    $UpdatesDownloaded = 0
    foreach($AvailableUpdate in $AvailableUpdatesList){
        #Find a match in the Targeted Updates list
        foreach($TargetedUpdate in $TargetedUpdates){
            if($TargetedUpdate.Title -eq $AvailableUpdate.Title) {
                if($AvailableUpdate.isDownloaded -eq $True) {
                    $UpdatesDownloaded = $UpdatesDownloaded + 1
                    New-Outputline -Message "Update Download Succeeded: $($AvailableUpdate.Title)"
                } else {
                    New-Outputline -Message "Update Download Failed: $($AvailableUpdate.Title)" -Type "Warning"
                }
            }
        }
    }

    if($UpdatesDownloaded -ne $UpdatesTargetedforInstall) {
        New-Outputline -Message "One or more updates failed to Download" -Type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    }
}

#Section 1 Step 6:  Install targeted updates

if($ProcessInstallTargetedUpdates -eq $True) {
    Try{
        $WUInstaller = $WUSession.CreateUpdateInstaller() 
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update Installer object - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    } 
}

if($ProcessInstallTargetedUpdates -eq $True) {
    Try{
        $WUInstaller.Updates = $TargetedUpdates
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to set the update collection on the Windows Update Installer object - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    } 
}

if($ProcessInstallTargetedUpdates -eq $True) {
    New-Outputline -Message "Starting Targeted Update Install"
    Try{
        $WUInstallation = $WUInstaller.Install()
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to start the Windows Update Downloads - $($ErrorMessage)" -type "Error"
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Stop further processing
        $ProcessInstallTargetedUpdates = $false
    } 
}

if($ProcessInstallTargetedUpdates -eq $True) {
    if($WUInstallation.Resultcode -eq 2) {
        New-Outputline -Message "Updates were installed"
        $ProcessRemediationCooldown = $True
    } else {
        New-Outputline -Message "Some updates were not installed" -type "Error"
    }

    if($WUInstallation.RebootRequired -eq $True) {
        New-Outputline -Message "A reboot is required to complete updates"
        $ProcessRebootToast = $True
    } else {
        New-Outputline -Message "A reboot is not required to complete updates"
    }
}

#Section 1 Step 7: Create a Toast Message
if($ProcessRebootToast -eq $True) {
    $ToastNotificationOK = New-ToastNotification -type "ToastReboot"
    if($ToastNotificationOK -eq $true) {
        New-Outputline -Message "Initiated Toast Notification for a reboot"
    } else {
        New-Outputline -Message "Toast Notification failed" -type "Error"
    }
}

If($ProcessRemediationCooldown -eq $true){
    #Set the remediation cooldown
    $WURemediationStatus = Set-WURemediationStatus
    If($WURemediationStatus.Status -eq $True) {
        New-Outputline -Message "Remediation cooldown set to $($WURemediationStatus.Date)"
    } else {
        New-Outputline -Message "Remediation cooldown not set" -type "Error"
    }
}

################################################
#Section 2: Output
################################################

# Section 2 Step 1: Upload the logs to Azure Log Analytics
#add a marker to the output
if($ErrorFlag -eq $true) {
    New-Outputline -Message "Error Detected" -Type "Error"
}else {
    New-Outputline -Message "Remediation Level $($RemediationLevel) Processed Successfully"
}

#Upload the logs
if ($ProcessUploadLogs -eq $True) {
    #Convert the log cache array to JSON
    $LogAnalyticsJSON = $OutputArray | ConvertTo-Json
    #Upload the log data
    $UploadLogAnalyticsData = New-LogAnalyticsData -WorkspaceID $LogAnalyticsWorkspaceID -SharedKey $LogAnalyticsSharedKey -LogBody ([System.Text.Encoding]::UTF8.GetBytes($LogAnalyticsJSON)) -LogType $Log_Type
    if($UploadLogAnalyticsData.Status -eq $false) {
        Write-Output "Error uploading Logs to Log Analytics"
        $ErrorFlag = $True
    }
}

# Section 2 Step 2: Write the output
#Compile the output
if($ErrorFlag -eq $true) {
    $OutputText = "Error Detected"
}else {
    $OutputText = "Remediation Level $($RemediationLevel) Processed Successfully"
}

#Write the output and signal the exit code
if($ErrorFlag -eq $true) {
    write-Output $OutputText
    Write-Error "Error Occurred when Running Remediation"
    Exit 1
} else {
    if($RunRemediation -eq $true) {
        write-Output $OutputText
        Exit 1
    } else {
        Write-Output $OutputText
        Exit 0
    }
}