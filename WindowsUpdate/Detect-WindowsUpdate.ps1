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
Filename:      Detect-WindowsUpdate.ps1
Documentation: https://tothecloudandbeyond.substack.com/
Execution Tested on: ProActive Remediation
Requires:      Windows 10 21H1
Purpose: A Pro-Active Remediation Script that detects issues with Windows Update
Versions:
1.0 - 28 February 2022
 - first public release
===========================================================================

.SYNOPSIS
A Pro-Active Remediation Script that detects issues with Windows Update

.DESCRIPTION
Process Execution:
Section 0: Setup
Section 1: Check Windows Update
Section 2: Clean-up and exit

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
#Create the Output Array - will be converted to a text output at the edn of the script
$OutputArray = New-Object System.Collections.ArrayList

#Set the Process flags
$ProcessWindowsUpdate = $true
$ProcessUploadLogs = $false
$RunRemediation = $False #Set the run remediation to false as the initial value
$ErrorFlag = $False


#Logging Variables
$LogAnalyticsWorkspaceID = "<Enter Workspace ID"
$LogAnalyticsSharedKey = "<Enter the Shared Key"

$Log_Type = "ProActive_WU_Detect"
$TimeStampField = ""
$ComputerName = ""
$UserName = ""
$Script:OutputEntry = 0

$OutputGUID = New-GUID #Generate an output guid to tie the messages from a particular run together

#Windows Update Search Parameters

$WUSearchParameter = 60 #Set how long to go back in the windows Update history in days
$WULastSearchWindow = 7
$WUCULastInstalledWindow = 35
$WUCUAvailableWindow = 3
#sets the number of items to retrieve to avoid trying to retrieve and endless query
$WUHistoryWindow = 60

#The registry key to store a flag
$RemediationFlagPath = "HKLM:\SOFTWARE\Deploy\ProActiveRemediation"
$RemediationFlag = "WURemediationDate"
$RemediationLevelFlag = "WURemediationLevel"
#Remediation Level 1 - Install targeted updates
#Remediation level 2 - Restart Windows Update Service
#Remediation Level 3 - TBC - Maybe clear the Software Distribution folders

#Remediation cooldown sets how many days between attempting to run the remediation
$RemediationCooldown = 7
$RemediationLevel = 1 #Default to level 1 remediation



#If Debug is enabled then messages are logged to screen immediately rather than wait until the end
if($DebugMode -eq $True) {
    $EnableDebug = $true
} else {
    $EnableDebug = $false
}



################################################
#Declare Functions
################################################

<#
    Determine whether the WU Remediation was run recently
#>

Function Get-WURemediationStatus {
    
    $FunctionReturn = New-Object -TypeName PSObject -Property @{
        'CooldownActive' = $True
        'Date' = "NA"
    }
    $CheckRemediationValue = $true

    if($CheckRemediationValue -eq $True) {
        if(Test-Path -Path $RemediationFlagPath -PathType Container) {
            #the registry flag path exists
        } else {
            $CheckRemediationValue = $False
            $FunctionReturn.CooldownActive = $False
        }
    }

    if($CheckRemediationValue -eq $True) {
        #Check that the remediation flag exists
        If($null -eq (Get-Item -Path $RemediationFlagPath).getvalue($RemediationFlag)) {
            #The remediation was not run recently
            $FunctionReturn.CooldownActive = $False
        } else {
            #Retrieve the value
            $RawRemediationValue = (Get-Item -Path $RemediationFlagPath).getvalue($RemediationFlag)
            #convert to a date value 
            try {
                $RemediationLastRunDate = [Datetime]::ParseExact($RawRemediationValue,"dd-MMM-yyyy-HH-mm-ss",$null)
            } catch {
                New-Outputline -Message "Unable to convert registry value ($($RawRemediationValue)) to a date value" -Type "Error"
                $CheckRemediationValue = $False
                $FunctionReturn.CooldownActive = $False
            }

            if($CheckRemediationValue -eq $true) {
                #Testing only
                #$RemediationLastRunDate = $RemediationLastRunDate.adddays(-2)
                #Set the date of the last remediation run
                $FunctionReturn.Date = "$(get-date -date $RemediationLastRunDate -Format "dd-MMM-yyyy HH-mm-ss")"
                $CooldownDate = (get-date).AddDays(-$RemediationCooldown)
                New-Outputline -Message "Cooldown date - $(get-date -date $CooldownDate -Format "dd-MMM-yyyy HH-mm-ss")"
                #Compare the Last Remediation date with the cooldown date
                if($CooldownDate -ge $RemediationLastRunDate) {
                    #Run the remediation if the last run date exceeds the cooldown date
                    $FunctionReturn.CooldownActive = $False
                }
            }
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
    #Incrementing Output Entry Number
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

<#
    Create a remediation flag
#>

Function Set-WURemediationLevel {
    param (
        [Parameter(Mandatory=$true)]
        [int]$Level
    )

    $FunctionReturn = New-Object -TypeName PSObject -Property @{
        'Status' = $True
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
    #creates a new item
    if($FunctionReturn.Status -eq $True) {
        Try {
            New-ItemProperty -Path $RemediationFlagPath -Name $RemediationLevelFlag -Value $Level -PropertyType DWORD -ErrorAction Stop -force
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-Outputline -Message "Creation of Remediation flag failed - $($ErrorMessage)" -type "Error"
            $FunctionReturn.Status = $False
        }
    }

    Return $FunctionReturn
}


################################################
#Section 0 - Setup
################################################

#Section 0 Step 1: Grab the logged in user from WMI
Try {
    $LoggedinUser = (Get-WmiObject -class win32_computersystem | select-object username).Username
} Catch {
    $ErrorMessage = $_.Exception.Message
    New-Outputline -Message "Error retrieving WMI query: $($ErrorMessage)" -type "Error"
    $Username = "Unknown"
}
if($Username -ne "Unknown") {
    if($loggedinUser.length -ne 0) {
        if($LoggedinUser -like "*\*") {
            $UserName = $LoggedinUser.Split("\")[1]
        } else {
            New-Outputline -Message "Username ($($LoggedinUser)) is an unknown format" -type "Error"
            $Username = "Unknown"
        }
    } else {
        New-Outputline -Message "Username not found" -type "Error"
        $Username = "Unknown"
    }
}
#Section 0 Step 2: Grab the computername from WMI
Try {
    $ComputerName = (Get-WmiObject -class win32_computersystem | select-object Name).Name
} Catch {
    $ErrorMessage = $_.Exception.Message
    New-Outputline -Message "Error retrieving WMI query: $($ErrorMessage)" -type "Error"
    $ComputerName = "Unknown"
}

################################################
#Section 1 - Check Windows Update
################################################


#Section 1 Step 1: Check the cooldown value
If($ProcessWindowsUpdate -eq $true){
    #Check the status of the remediation cooldown
    $WURemediationCooldownActive = Get-WURemediationStatus
    if ($WURemediationCooldownActive.CooldownActive -eq $false) {
        $ProcessWindowsUpdate = $true
        New-Outputline -Message  "Windows Update Remediation Cooldown Inactive - last run $($WURemediationCooldownActive.Date)"
    } else {
        $ProcessWindowsUpdate = $false
        New-Outputline -Message  "Windows Update Remediation Cooldown Active - last run $($WURemediationCooldownActive.Date)"

    }
}

#Section 1 Step 2: Check whether the Windows Update service is started
If($ProcessWindowsUpdate -eq $true){
    try {
        $WUServiceStarted = (Get-Service -Name wuauserv).status
    } catch{
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to query Windows Update service - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }
}

If($ProcessWindowsUpdate -eq $true){
    Switch ($WUServiceStarted) {
        "Running" {
            New-Outputline -Message  "Windows Update service is running"
        }
        "Stopped" {
            New-Outputline -Message  "Windows Update service is stopped" -Type "Warning"
            #note that this might be normal it depends on whether the service has been called recently
        }
        "StartPending" {
            New-Outputline -Message  "Windows Update service is pending start" -Type "Warning"
            #Stop further checks and move to restart the windows Update Service
            $ProcessWindowsUpdate = $false
            $RunRemediation = $True
            #Set Remediation to Level 2
            $RemediationLevel = 2
        }
        "StopPending" {
            New-Outputline -Message  "Windows Update service is pending stop" -Type "Warning"
            #Stop further checks and move to restart the windows Update Service
            $ProcessWindowsUpdate = $false
            $RunRemediation = $True
            #Set Remediation to Level 2
            $RemediationLevel = 2
        }
    }
}

#Section 1 Step 3: Create a Windows Update object
If($ProcessWindowsUpdate -eq $true){
    #Get the Windows Update Object
    Try{
        $WindowsUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to get Windows Update COM object - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }
}

#Section 1 Step 4: Check whether the Windows update service has been queried recently
If($ProcessWindowsUpdate -eq $true){
    #Query the Windows Update status
    Try{
        $WUResults = $WindowsUpdate.Results
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to query Windows Update result status from COM - $($ErrorMessage)"  -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }
}

If($ProcessWindowsUpdate -eq $true){
    #
    if (!($null -eq $WUResults.LastSearchSuccessDate)) {
        $WULastQueryDate = $WUResults.LastSearchSuccessDate
        if((get-date).adddays(-$WULastSearchWindow) -ge $WULastQueryDate){
            New-Outputline -Message  "Windows Update Search Last Succeeeded more than $($WULastSearchWindow) days ago ($($WULastQueryDate))" -type "Warning"
            #Trigger the remediation
            $RunRemediation = $True
            #Set Remediation to Level 1
            $RemediationLevel = 1
        } else {
            New-Outputline -Message  "Windows Update Search Last Succeeded recently ($($WULastQueryDate))"
        }
    } Else {
        New-Outputline -Message  "Failed to query Windows Update result status from COM - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }
}

#Section 1 Step 5: Check the status of recent Windows Updates
If($ProcessWindowsUpdate -eq $true){
    #Create a Windows Update session object
    Try{
        $WUSession = New-Object -ComObject Microsoft.Update.Session
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update service session object from COM - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }   
}

If($ProcessWindowsUpdate -eq $true){
    #Create a Windows Update Searcher object
    Try{
        $WUSearcher = $WUSession.CreateUpdateSearcher()
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update Searcher object - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }   
}

If($ProcessWindowsUpdate -eq $true){
    #Get the total history count
    Try{
        $WUHistoryCount = $WUSearcher.GetTotalHistoryCount()
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to retrieve the Windows Update history count - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }
}
If($ProcessWindowsUpdate -eq $true){
    if($null -eq $WUHistoryCount) {
        New-Outputline -Message  "Windows Update history count was null" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 1
        $RemediationLevel = 1
    } else {
        #Determine the query parameters to work out how many entries to retrieve
        if($WUHistoryCount -lt $WUHistoryWindow) {
            $WUQueryEnd = $WUHistoryCount
        } else {
            $WUQueryEnd = $WUHistoryWindow
        }
    }
}

If($ProcessWindowsUpdate -eq $true){
    #Search windows Update
    Try{
        $WUHistory = $WUSearcher.QueryHistory(0,$WUQueryEnd) | Where-Object {($_.Date -ge (Get-date).AddDays(-$WUSearchParameter))} | Sort-Object Date
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to retrieve the Windows Update history - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 1
        $RemediationLevel = 1
    }   
}

#Check the search results
If($ProcessWindowsUpdate -eq $true){
    If($null -eq $WUHistory) {
        New-Outputline -Message  "Windows Update history was null" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 1
        $RemediationLevel = 1
    } else {
        if($WUHistory.Count -eq 0) {
            New-Outputline -Message  "No Windows Update history entries were retrieved - $($ErrorMessage)" -type "Error"
            #Stop any further processing
            $ProcessWindowsUpdate = $false
            #Set the error flag so that an error status is added to the log
            $ErrorFlag = $True
            #Trigger the remediation
            $RunRemediation = $True
            #Set Remediation to Level 1
            $RemediationLevel = 1
        } else {
            New-Outputline -Message "Retrieved $($WUHistory.Count) Windows Update History Entries from the last $($WUSearchParameter) days"
        }
    }
}

#Process the search results
If($ProcessWindowsUpdate -eq $true){
    $UpdateCount = 0
    $UpdateSucceededCount = 0
    $UpdateTotalCount = 0
    $SuccessfulUpdateDate = (Get-date).AddDays(-30)
    #Set the cumulative update last succeeded date to a default value
    $CumulativeUpdateLastSucceeded = (Get-date).AddDays(-$WUCULastInstalledWindow)

    Do {
        #Check whether to ignore the update or not by excluding some types of updates
        $IgnoreUpdate = $False
        if($WUHistory[$UpdateCount].Title.StartsWith("Windows Malicious Software Removal Tool") -eq $true) {
            $IgnoreUpdate = $True
        }
        if($WUHistory[$UpdateCount].Title.StartsWith("Security Intelligence Update for Microsoft Defender Antivirus") -eq $true) {
            $IgnoreUpdate = $True
        }
        #Check whether the update is a cumulative update
        if($WUHistory[$UpdateCount].Title.Contains("Cumulative Update for Windows") -eq $True){
            $CumulativeUpdate = $True
        } else {
            $CumulativeUpdate = $False
        }


        if($IgnoreUpdate -eq $false) {
            $UpdateTotalCount = $UpdateTotalCount + 1
           
            #Determine whether the update failed
            Switch($WUHistory[$UpdateCount].ResultCode) {
                1 {
                    #In Progress
                    $UpdateSucceeded = $True
                    $UpdateState = "In Progress"
                }
                2 {
                    #Succeeded
                    $UpdateSucceeded = $true
                    $UpdateState = "Succeeded"
                }
                3 {
                    #Succeeded with errors
                    $UpdateSucceeded = $True
                    $UpdateState = "Succeeded with errors"
                }
                4 {
                    #failed
                    $UpdateSucceeded = $false
                    $UpdateState = "Failed"
                }
                5 {
                    #aborted
                    $UpdateSucceeded = $false
                    $UpdateState = "Aborted"
                }
                default {
                    $UpdateSucceeded = $True
                    $UpdateState = "Update state: $($WUHistory[$UpdateCount].ResultCode)"
                }
            }
            #Add the install state to the output
            if($UpdateSucceeded -eq $false) {
                New-Outputline -Message  "Windows Update Installation $($UpdateState) $(get-date -date $WUHistory[$UpdateCount].Date -Format "dd-MMM-yyyy") for $($WUHistory[$UpdateCount].title)" -Type "Warning"
            } else {
                $UpdateSucceededCount = $UpdateSucceededCount + 1
                New-Outputline -Message "Windows Update Installation $($UpdateState) $(get-date -date $WUHistory[$UpdateCount].Date -Format "dd-MMM-yyyy") for $($WUHistory[$UpdateCount].title)"

                if($WUHistory[$UpdateCount].Date -gt $SuccessfulUpdateDate) {
                    $SuccessfulUpdateDate = $WUHistory[$UpdateCount].Date
                }
                if ($CumulativeUpdate -eq $True) {
                    if($WUHistory[$UpdateCount].Date -gt $CumulativeUpdateLastSucceeded) {
                        $CumulativeUpdateLastSucceeded = $WUHistory[$UpdateCount].Date
                    }
                }
            }

            if($UpdateSucceeded -eq $false) {
                #If the update failed then search forward to find out whether the update succeeded in future
                if(($UpdateCount+1) -eq $WUHistory.count) {
                    #do not attempt to move forward in the array - update has failed and not recovered
                } else {
                    $Forwardcount = $UpdateCount + 1
                    $ExitLoop = $False
                    Do {
                        #Check whether the update is the same update
                        if($WUHistory[$UpdateCount].Title -eq $WUHistory[$Forwardcount].title) {
                            if($WUHistory[$Forwardcount].ResultCode -eq 2) {
                                #The update succeeded at a later date so ignore
                                $UpdateSucceeded = $True
                                New-Outputline -Message "Windows Update Installation succeeded after a previous failure $(get-date -date $WUHistory[$UpdateCount].Date -Format "dd-MMM-yyyy") for $($WUHistory[$UpdateCount].title)"
                            }
                        }
                        if($UpdateSucceeded -eq $True) {
                            $ExitLoop = $True
                        } else {
                            $Forwardcount = $Forwardcount + 1
                            if($Forwardcount -eq $WUHistory.count) {
                                $ExitLoop = $True
                            }
                        }
                    } until($ExitLoop -eq $True)
                }
            }
            if($UpdateSucceeded -eq $False) {
                #Trigger the remediation if the update was a cumulative update
                if ($CumulativeUpdate -eq $True) {
                    $RunRemediation = $True
                }
            }             
        }
        $UpdateCount = $UpdateCount + 1
    } until($UpdateCount -eq $WUHistory.count)

    #Add an informational message
    New-Outputline -Message  "Windows Updates Installed in last $($WUSearchParameter) days: $($UpdateSucceededCount) installations succeeded in $($UpdateTotalCount) attempts"
    #check the last successful update date is within 30 days
    if($SuccessfulUpdateDate -gt (Get-date).AddDays(-$WUSearchParameter)) {
        #Add an informational message
        New-Outputline -Message  "Windows Updates Last successfully installed on $(get-date -date $SuccessfulUpdateDate -Format "dd-MMM-yyyy")"
    } else {
        #Only run remediations for missing cumulative updates
        #Add an informational message
        New-Outputline -Message  "Windows Updates Last successfully installed more than $($WUSearchParameter) days ago" -type "Warning"
    }
    if($CumulativeUpdateLastSucceeded -gt (Get-date).AddDays(-$WUCULastInstalledWindow)) {
        #Add an informational message
        New-Outputline -Message  "A Cumulative Update was last successfully installed on $(get-date -date $CumulativeUpdateLastSucceeded -Format "dd-MMM-yyyy")"
    } else {
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 1
        $RemediationLevel = 1
        #Add an informational message
        New-Outputline -Message  "A Cumulative Update was last successfully installed more than $($WUSearchParameter) days ago" -type "Warning"
    } 
}

#Section 1 Step 6: Check whether a reboot is required
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
         #Trigger the remediation
         $RunRemediation = $True
         #Set Remediation to Level 2
         $RemediationLevel = 2
    }   
}

If($ProcessWindowsUpdate -eq $true){
    if(!($null -eq $WURebootStatus.RebootRequired)) {
        if($WURebootStatus.RebootRequired -eq $True)  {
            New-Outputline -Message "A reboot to install Windows Updates is pending"
             #Stop any further processing
             $ProcessWindowsUpdate = $false
             #Set the error flag so that an error status is added to the log
             $ErrorFlag = $True
             #Trigger the remediation
             $RunRemediation = $True
             #Set Remediation to Level 1
             $RemediationLevel = 1
        } else{
            New-Outputline -Message "A reboot to install Windows Updates is not required"
        }
    } else {
        New-Outputline -Message  "Failed to query Windows Update reboot status - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }
}

#Section 1 Step 7: Look for updates that are available
If($ProcessWindowsUpdate -eq $true){
    #Create a Windows Update Searcher object
    Try{
        $WUSearcherAvailableUpdates = $WUSession.CreateUpdateSearcher()
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to create a Windows Update Searcher object - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }   
}

If($ProcessWindowsUpdate -eq $true){
    #search for the available updates
    Try{
        $AvailableUpdatesList = ($WUSearcherAvailableUpdates.Search("IsInstalled=0 and IsHidden = 0")).Updates
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-Outputline -Message  "Failed to search for available windows Updates - $($ErrorMessage)" -type "Error"
        #Stop any further processing
        $ProcessWindowsUpdate = $false
        #Set the error flag so that an error status is added to the log
        $ErrorFlag = $True
        #Trigger the remediation
        $RunRemediation = $True
        #Set Remediation to Level 2
        $RemediationLevel = 2
    }   
}

If($ProcessWindowsUpdate -eq $true){
    $AvailableUpdates = 0
    $AvailableCumulativeUpdates = 0
    foreach($Update in $AvailableUpdatesList){
        if($Update.Deploymentaction -eq 1) {
            $AvailableUpdates = $AvailableUpdates +1
            #Check the date 
            $UpdateGoodDate = $True
            try{
                $UpdateLastDeploymentChangeTime = [Datetime]::ParseExact($Update.LastDeploymentChangeTime, "MM/dd/yyyy hh:mm:ss", $null)
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-Outputline -Message  "Failed to convert date for Available Update: $($Update.Title) - Date value: $($Update.LastDeploymentChangeTime) - $($ErrorMessage)" -type "Error"
                $UpdateGoodDate = $false
            }
            if ($UpdateGoodDate -eq $false) {
                #set the date to whatever the date was in plain text if the date value was unknown
                $UpdateLastDeploymentChangeTime = "$($Update.LastDeploymentChangeTime)"
                $FormattedUpdateLastDeploymentChangeTime = "$($Update.LastDeploymentChangeTime)"
            } else {
                $FormattedUpdateLastDeploymentChangeTime = get-date -date $UpdateLastDeploymentChangeTime -Format "dd-MMM-yyy"
            }
            #Determine whether the available update is a cumulative update
            if($Update.Title.Contains("Cumulative Update for Windows") -eq $True) {

                if ($UpdateGoodDate -eq $true) {
                    #check whether the update needs to be installed
                    if($UpdateLastDeploymentChangeTime -lt (Get-date).AddDays(-$WUCUAvailableWindow)){
                        New-Outputline -Message "Cumulative update ready for installation: $($Update.Title) - Deployment change time $($FormattedUpdateLastDeploymentChangeTime)"
                        $AvailableCumulativeUpdates = $AvailableCumulativeUpdates + 1
                        #Trigger the remediation
                        $RunRemediation = $True
                        #Set Remediation to Level 1
                        $RemediationLevel = 1
                    } else {
                        New-Outputline -Message "Cumulative update waiting for installation: $($Update.Title) - Deployment change time $($FormattedUpdateLastDeploymentChangeTime)"
                    }
                } else {
                    New-Outputline -Message "Cumulative update ready for installation: $($Update.Title) - Deployment change time $($FormattedUpdateLastDeploymentChangeTime)"
                    $AvailableCumulativeUpdates = $AvailableCumulativeUpdates + 1
                    #Trigger the remediation
                    $RunRemediation = $True
                    #Set Remediation to Level 1
                    $RemediationLevel = 1
                }
            } else {
                New-Outputline -Message "Available Update waiting for installation: $($Update.Title) - Deployment change time $($FormattedUpdateLastDeploymentChangeTime)"    
            }
        } else {
            New-Outputline -Message "Available Update: $($Update.Title), Type: $($Update.Type), Action: $($Update.DeploymentAction)"
        }
    }
    if($AvailableUpdates -eq 0) {
        New-Outputline -Message "No available updates found"
    } else {
        New-Outputline -Message "Found $($AvailableUpdates) update(s) that are available for deployment"
        If($AvailableCumulativeUpdates -eq 0) {
            New-Outputline -Message "No available Cumulative Updates found"
        } else {
            New-Outputline -Message "Found $($AvailableCumulativeUpdates) Cumulative Update(s) that are available for deployment"
        }
    }
}

#Section 1 Step 8: Set the Remediation Level in the registry
If($ProcessWindowsUpdate -eq $true){
    if($RunRemediation -eq $true) {
        $SetRemediationLevel = Set-WURemediationLevel -level $RemediationLevel
        If($SetRemediationLevel.Status -eq $True) {
            New-Outputline -Message "Remediation Level set to Level $($RemediationLevel)"
        } else {
            New-Outputline -Message "Failed to set Remediation Level to Level $($RemediationLevel)" -Type "Error"
        }
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
    if($RunRemediation -eq $true) {
        New-Outputline -Message "Remediation Level $($RemediationLevel) Required"
    } else {
        New-Outputline -Message "Remediation Not Required"
    }
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
    if($RunRemediation -eq $true) {
        $OutputText = "Remediation Level $($RemediationLevel) Required"
    } else {
        $OutputText = "Remediation Not Required"
    }
}

#Write the output and signal the exit code
if($ErrorFlag -eq $true) {
    write-Output $OutputText
    Write-Error "Error Occurred when Running Detection"
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





