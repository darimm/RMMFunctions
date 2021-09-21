# RMMFunctions
A collection of useful RMM functions - Developed for DattoRMM, but useful anywhere
  
To import the module in a cript use the following codeblock and modify the event source.

```
##Initial Setup##
$env:RMMEventSource = "CHANGEME - Template"
Import-Module "<path-to-module>\UniversalRMMFunctions.psm1"
##End Enitial Setup##
```

This will allow using Write-EVLog to log messages to the Event Log. it is
preferable to use Write-Append for creating an event log message, as this will
log your string to the console for the RMM platform to output as part of stdout
as well as append the string, with a built in linebreak to the existing log 
variable

eg:

```
$myLogVariable = Write-Append "Beginning my Log"
...
$myLogVariable += Write-Append "Some useful status information"
...
$myLogVariable += Write-Append "All done doing whatever we were doing"
Write-EVLog $myLogVariable
```
  
## Function Documentation
### Write-LogMessage  
This function is typically not used outside of the Write-EVLog function provided in the example above and by the template. It is an implementation wrapper of Write-EventLog that also provides Verbose output to the console if the Verbose stream is enabled.  
### Write-EVLog
This function is used to write events to the event log, A Message is mandatory, and optionally you can provide -IsError and -TriggerAutomation which will  
change the EventID used. See the function definition for additional details.
### New-RMMEventSource 
Creates a new Event Source in the Windows Event Viewer that can be logged to. Function handles checking to see if the log already exists and logs a message if it does. See the example above or the Template.ps1 for example use cases.  
### Write-Append 
Utility Function, typically used with += to append the contents of a string, and also echo that contents to the console. Automatically appends a CRLF at the end of the provided string for the actual append functionality. Does not output the extra CRLF to console.  
### Install-MSI
Silently installs an MSI. Additional Parameters can be provided via -AdditionalParams (for things like ALLUSERS=1 etc). Specifying -OutputLog will send the Install Log to the console for script output.  
### Set-MaximumTLS 
Ensures that Powershell is configured to utilize the maximum version of TLS possible (SSL3 < TLS1 < TLS1.1 < TLS1.2 < TLS1.3)  
### New-FileDownload
Wraps the System.Net.WebClient class to download a file. Returns $true if the file downloaded was successful and the file exists, $false if not.  
### Test-FreeSpace
Returns $true if there is more freespace than the specified value in GB, otherwise returns $false  
### Test-64bit
Returns $true if the system is 64 bit. Otherwise returns $false  
### Test-32bit 
Returns $true if the system is 32 bit. Otherwise returns $false  
### Get-WindowsVersion 
Returns a string containing the Windows Version (eg 6.1.7601, 10.0.19041.0 etc.)  
### Test-Windows10 
Returns $true if OS is Windows 10, otherwise $false  
### Test-Windows8.1 
Returns $true if OS is Windows 8.1, otherwise $false  
### Test-Windows8 
Returns $true if OS is Windows 8, otherwise $false  
### Test-Windows7 
Returns $true if OS is Windows 7, otherwise $false  
### Test-Vista 
Returns $true if OS is Windows Vista, otherwise $false  
### Test-IsServer2008 
Returns $true if OS is Windows Server 2008, otherwise $false  
### Test-IsServer2008R2 
Returns $true if OS is Windows Server 2008R2, otherwise $false  
### Test-IsServer2012 
Returns $true if OS is Windows Server 2012, otherwise $false  
### Test-IsServer2012R2 
Returns $true if OS is Windows Server 2012R2, otherwise $false  
### Test-IsServer2016 
Returns $true if OS is Windows Server 2016, otherwise $false  
### Test-IsServer2019 
Returns $true if OS is Windows Server 2019, otherwise $false  
### Test-Server
Returns $true if OS is Windows 10, otherwise $false  
### Test-IsServer
Returns $true if OS is a Windows Server OS, otherwise $false  
### Test-IsPortable
Returns $true if computer hardware is a laptop or tablet, $false otherwise  
## Test-IsDomainController 
Returns $true if computer is a Windows AD Domain Controller, otherwise $false  
## Test-License
Returns $true if computer has a valid license, otherwise $false  
## Test-ServiceExists 
Returns $true if the computer has the named service, regardless of whether it is enabled/running, otherwise $false  
## Test-ServiceRunning 
Returns $true only if the named service exists and is currently running. Otherwise returns $false  
## Test-InstalledSoftwareWMI 
This should not be used unless there is a very specific need. It is much slower than Test-InstalledSoftware, and provides less functionality. Return values are the same as Test-InstalledSoftware  
## Test-InstalledSoftware 
Returns $true if the specified software is installed. Name must match exactly (but is not case sensitive). Returns $false if the software is not installed.  
## Get-UninstallString
Returns the UninstallString of an installed application. Application Name must match exactly (but is not case sensitive). Returns an empty string if no match is found.  
## Get-ApplicationList
Returns an array of Application Names that match the specified search pattern. Supplying * to this function will get a full list of everything installed.  
## Convert-BinToHex 
Converts Binary to Hexidecimal strings, for use with REG_BINARY types. Return Value is a string.  
## Convert-HexToBin 
Converts a Hexidecimal string to Binary for use with REG_BINARY types. Return Value is an array of bits that can be written to the registry.  
## Test-KBInstalled 
Input value is just the # of the KB in question (eg 12345678 not KB12345678), returns $true if installed, $false otherwise.  
## ConvertFrom-Json20
Converts JSON into Powershell Objects. Works with Powershell 2.0 (Convert-FromJSON does not). Returns an object composed of whatever properties were in the JSON.  
## Backup-EventLog
Backs up an Event Log, attempts to compress it with 7zip. Return Value is an Object with the properties "Success" which is a boolean value indicating whether the backup was successful or not, and LogMessage, which is properly formatted for Write-EVLog/appending to an existing logMessage.  
## Compress-7Zip 
Compress Files into a 7zip archive. Takes exactly 2 arguements. OutputFile which is the name of the .7z archive you wish to create, and Source which is a string specifying what you want to archive. This can include standard wildcards or be a folder etc. Returns $true if the files were successfully compressed, otherwise $false. 
## Expand-7Zip 
Expands zip or 7z archives. Only 2 arguments required. OutputFile which is the name or path you want to extract the files to, and Source which is a string specifying the current archive you want to extract. Returns $true if the files were successfully extracted, otherwise $false.
## Test-RegistryKey
Checks if the registry key exists. Requires only 1 paramter, the registry path, $key. Returns $true if key exists, otherwise $false.
## Test-RegistryValue
Checks if the registry value exists at the given key. Requires 2 paramters, the $key and the $value. Returns $true if it exists, otherwise $false.
## Test-RegistryValueNotNull 
Checks if the requested $value is not null . Requires 2 paramters, the $key and the $value. Returns $true if the value is not null, otherwise $false.
## Test-RebootPending
Checks various places in order to determine if a reboot is pending on a machine. Returns $true if reboot needed, otherwise $false.

## Write-MonitorResult
Takes the supplied OutputResultName and Message and generates a formatted monitor result. Note the supplied Message must be a single line. Optionally, will take a provided diagnostic message for display in the monitor.