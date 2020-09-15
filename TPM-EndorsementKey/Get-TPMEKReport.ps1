Param(
    [Parameter(Mandatory)]
    [string]$OutputFile
)

Update-MSGraphEnvironment -SchemaVersion beta

Connect-MSGraph

#Create an array for the output
$TPMEKOutput = New-Object System.Collections.ArrayList

#Get the details of the TPM report
Write-Host "Retrieving TPM Report Device States"
$AllResultsRetrieved = $False
$ResultsRetrieved = 0
do {
    If ($ResultsRetrieved -eq 0) {
        #Set the 'TPM EK URL for the first run
        $TPMInvokeURL = 'deviceManagement/deviceHealthScripts/<guid>/deviceRunStates?'
    }
    #Retrieve the results
    $TPMEKResults = Invoke-MSGraphRequest -HttpMethod GET -Url $TPMInvokeURL

    #Process the returned data
    $TPMEKResultData = $TPMEKResults.Value
    Foreach ($TPMResult in $TPMEKResultData) {
        If (($TPMResult.detectionState -eq "fail") -and ($TPMResult.remediationState -eq "remediationFailed")) {
            $SerialNoIndex = $TPMResult.preRemediationDetectionScriptOutput.indexof("Number") + 7
            $SerialNo = $TPMResult.preRemediationDetectionScriptOutput.Substring($SerialNoIndex,($TPMResult.preRemediationDetectionScriptOutput.Length-$SerialNoIndex))
            $TempTPMOutput = New-Object -TypeName PSObject -Property @{
                'detectionState' = $TPMResult.detectionState
                'remediationState' = $TPMResult.remediationState
                'lastStateUpdateDateTime' = $TPMResult.lastStateUpdateDateTime
                'lastSyncDateTime' = $TPMResult.lastSyncDateTime
                'preRemediationDetectionScriptOutput' = $TPMResult.preRemediationDetectionScriptOutput
                'SerialNo' = $SerialNo
            }
            $TPMEKOutput.Add($TempTPMOutput) | out-null
        }
    }

    If ($TPMEKResults."@odata.count" -eq 1000) {
        Write-Host "Retrieving next 1000 results"
        $ResultsRetrieved = $ResultsRetrieved + $TPMEKResults."@odata.count"
        $TPMInvokeURL= $TPMEKResults."@odata.nextLink"
    } else {
        $ResultsRetrieved = $ResultsRetrieved + $TPMEKDetails."@odata.count"
        $AllResultsRetrieved = $True
        write-host "Processed $($ResultsRetrieved) device results"
    }

    
} until ($AllResultsRetrieved -eq $True)

Write-Host "Retrieved $($TPMEKOutput.count) Devices with failed TPMs"

$TPMEKOutput | Select-Object SerialNo,detectionState,remediationState,lastStateUpdateDateTime,lastSyncDateTime,preRemediationDetectionScriptOutput | Sort SerialNo | Export-Csv -notypeinformation $OutputFile









