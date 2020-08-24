$Hardware_Model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
$Hardware_Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
$Hardware_Serial = (Get-CimInstance -ClassName Win32_bios).serialnumber

 

$EndorsementKey = Get-TpmEndorsementKeyInfo

 

If($null -eq $EndorsementKey) {
    #Endrorsement Key information not returned
    Write-Output "Endorsement Key Information Not Returned for $Hardware_Model $Hardware_Manufacturer with Serial Number $Hardware_Serial"
    Exit 1
} else {
    If ($EndorsementKey.ManufacturerCertificates.count -gt 0) {
        Write-Output "Endorsement Key present for $Hardware_Model $Hardware_Manufacturer with Serial Number $Hardware_Serial. Issuer Information $($EndorsementKey.ManufacturerCertificates[0].issuer)"
        Exit 0
    } else {
        Write-Output "Endorsement Key not present for $Hardware_Model $Hardware_Manufacturer with Serial Number $Hardware_Serial"
        Exit 1
    }
}