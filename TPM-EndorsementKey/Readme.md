##TPM Endorsement Key Detection##

A simple Pro-Active Remediation script to detect devices that are missing a TPM Endorsement Key. This script was created in response to an issue where newly built devices with an Intel TPM do not automatically download an Endorsement Key using the Intel iCLS client. The fault has been tracked to an updated Intel iCLS client that appeared on Windows Update in July 2020. Unfortunately an unknown number of devices were deployed in the field before the issue was identified. 

Worse the only remedy that we have found so far is a complete re-image with a Windows 10 1909 image with the working drivers slipstreames. 

The Proactive Remediation package contains a single detection script because a device will need to be rebuilt if the TPM EK is missing. However the package does provide a mechanism of identifying the devices.
