
Function Write-LogMessage {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EventSource,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [int]$EventID,
    [switch]$IsError
  )

  #Set the type of Event entry that will be written.
  if ($IsError.IsPresent) {
    $entryType = [System.Diagnostics.EventLogEntryType]::Error 
  } else {
    $entryType = [System.Diagnostics.EventLogEntryType]::Information
  }
  
  $strLength = 0 
  while ($strLength -le ($Message.Length-30000)) {
    Write-EventLog -LogName $LogName `
      -Source $EventSource `
      -EntryType $entryType `
      -EventID $EventID `
      -Message $currentChunk
    Write-Verbose "$(Get-date -Format 'MM/dd/yyyy HH:mm K') [$($entryType.ToString())] $($message.Substring($strLength,30000))"
    $strLength+=30000
  }
  Write-EventLog -LogName $LogName `
    -Source $EventSource `
    -EntryType $entryType `
    -EventID $EventID `
    -Message $message.Substring($strLength)
  Write-Verbose "$(Get-date -Format 'MM/dd/yyyy HH:mm K') [$($entryType.ToString())] $($message.Substring($strLength))"
}

Function New-RMMEventSource {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Source
  )
  if (!([System.Diagnostics.EventLog]::Exists("UniversalRMM") -and [System.Diagnostics.EventLog]::SourceExists($Source))) {
    try {
      New-EventLog -LogName "UniversalRMM" `
        -Source $Source `
        -ErrorAction Stop  
      Write-LogMessage -LogName "UniversalRMM" `
        -Message "Setting Up Windows Event Log Source $($Source)...`r`nEvent Log Source registered successfully. Continuing." `
        -EventSource $Source `
        -EventID 0
    } catch {
      Write-Error "Unable to set up UniversalRMM Event Log Source. Critical Error."
      Exit 1
    }
  Limit-EventLog -LogName "UniversalRMM" -MaximumSize 1GB
  }
}

Function Write-EVLog {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
    [switch]$IsError,
    [switch]$TriggerAutomation
  )
  if ($TriggerAutomation.IsPresent -and $IsError.IsPresent) {
    Write-LogMessage -LogName "UniversalRMM" -EventSource $env:RMMEventSource -EventID 20 -Message $Message -IsError
  } elseif ($TriggerAutomation.IsPresent -and (!($IsError.IsPresent))) {
    Write-LogMessage -LogName "UniversalRMM" -EventSource $env:RMMEventSource -EventID 30 -Message $Message 
  } elseif ((!($TriggerAutomation.IsPresent)) -and $IsError.IsPresent) {
    Write-LogMessage -LogName "UniversalRMM" -EventSource $env:RMMEventSource -EventID 10 -Message $Message -IsError
  } else {
    Write-LogMessage -LogName "UniversalRMM" -EventSource $env:RMMEventSource -EventID 5 -Message $Message
  }
}

Function Write-Append {
  param (
    [Parameter(Mandatory = $true,ValueFromPipeline=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$Text
  )
  Write-Host $Text
  return "$($Text)`r`n"
}

function Get-DattoID {
  return (Get-ItemProperty -Path HKLM:\SOFTWARE\CentraStage -Name DeviceID).DeviceID
}

Function Install-MSI
{
Param (
  [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
  [ValidateNotNullOrEmpty()]
  [System.IO.FileInfo]$File,
  [String[]]$AdditionalParams,
  [Switch]$OutputLog
)
  $DateStamp = get-date -Format yyyyMMddTHHmmss
  $logFile = "$($env:UniversalRMMPath)\{0}-{1}.log" -f $file.name,$DateStamp
  $MSIArguments = @(
    "/i",
    ('"{0}"' -f $file.fullname),
    "/qn",
    "/norestart",
    "/L*v",
    $logFile
  )
  if ($additionalParams) {
    $MSIArguments += $additionalParams
  }
  Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
  if ($OutputLog.IsPresent) {
    $logContents = get-content $logFile
    Write-Output $logContents
  }
}

Function Set-MaximumTLS {
  add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(

            ServicePoint srvPoint, X509Certificate certificate,

            WebRequest request, int certificateProblem) {
            return true;
    }
    }
"@
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'SSL3,Tls'
  } catch {}
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'SSL3,Tls,Tls11'
  } catch {}
  try { #This fixes a lot of weird 2008R2/Windows 7 problems
    [Net.ServicePointManager]::SecurityProtocol =  [Enum]::ToObject([Net.SecurityProtocolType], 3072)
  } catch {}
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'SSL3,Tls,Tls11,Tls12'
  } catch {}
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'SSL3,Tls,Tls11,Tls12,Tls13'
  } catch {}
}

Function New-FileDownload {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Url,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LocalFilePath
  )
  Set-MaximumTLS
  $webClient = New-Object System.Net.WebClient
  $webClient.DownloadFile($Url,$LocalFilePath)
  if (Test-Path -Path $LocalFilePath) {
    Write-Verbose "File Downloaded Successfully: $LocalFilePath"
    return $true
  } else {
    Write-Verbose "File Download Failed"
    return $false
  }
}

Function Test-FreeSpace {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [int]$MinimumAvailableDiskSpaceInGB
  )
  $filter = "DeviceID='$($env:SystemDrive)'"
  If (!((Get-WmiObject Win32_LogicalDisk -Filter $filter | select-object -expand freespace)/1GB -ge $MinimumAvailableDiskSpace)) {
    return $false
  }
  return $true
}

Function Test-64bit {
  return [System.Environment]::Is64BitOperatingSystem
}

Function Test-32bit {
  return !([System.Environment]::Is64BitOperatingSystem)
}

Function Get-WindowsVersion {
  return -join [System.Environment]::OSVersion.Version, ''
}

Function Test-Windows10 {
  return (([System.Environment]::OSVersion.Version -gt (New-Object 'Version' 10,0)) -and (!(Test-IsServer)))
}

Function Test-Windows8 {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,2) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,3)) -and (!(Test-IsServer)))
}

Function Test-Windows8.1 {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,3) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,4)) -and (!(Test-IsServer)))
} 


Function Test-Windows7 {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,1) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2)) -and (!(Test-IsServer)))
}

Function Test-Vista {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,1)) -and (!(Test-IsServer)))
}

Function Test-IsServer {
  return ((get-wmiobject win32_operatingsystem).name -match 'Server')
}

Function Test-IsServer2008 {
  (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,1)) -and (Test-IsServer))
}

Function Test-IsServer2008R2 {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,1) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2)) -and (Test-IsServer))
}

Function Test-IsSBS2011 {
  return (Test-IsServer2008R2 -and ((get-wmiobject win32_operatingsystem).name -match 'Small'))
}

Function Test-IsServer2012 {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,2) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,3)) -and (Test-IsServer) -and
  (!((get-wmiobject win32_operatingsystem).name -match 'R2')))
}

Function Test-IsServer2012R2 {
  return (([System.Environment]::OSVersion.Version -ge (New-Object 'Version' 6,2) -and 
  [System.Environment]::OSVersion.Version -lt (New-Object 'Version' 6,4)) -and (Test-IsServer) -and ((get-wmiobject win32_operatingsystem).name -match 'R2'))
}

Function Test-IsServer2016 {
  return (([System.Environment]::OSVersion.Version -eq (New-Object 'Version' 10,0,14393,0)) -and (Test-IsServer))
}

Function Test-IsServer2019 {
  return (([System.Environment]::OSVersion.Version -eq (New-Object 'Version' 10,0,17763,0)) -and (Test-IsServer))
}

Function Test-IsPortable {
  if (Get-WmiObject -Class Win32_SystemEnclosure | Where-Object {
    $_.ChassisTypes -eq 9 -or $_.ChassisTypes -eq 10 -or $_.ChassisTypes -eq 14}) {
      return $true
    } 
  return $false
}

Function Test-IsDomainController {
  return ((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2)
}

Function Test-License {
  $varLicense = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object PartialProductKey).licensestatus
  if ($varLicense -eq 1) { 
    return $true
  } 
  return $false
}

Function Test-ServiceExists {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName
  )
  
  $serviceResult = Get-Service $ServiceName -ErrorAction SilentlyContinue
  if ($serviceResult) {
    return $true
  }
  return $false
}

Function Test-ServiceRunning {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName
  )
  $serviceResult = Get-Service $ServiceName -ErrorAction SilentlyContinue
  if ($serviceResult) {
    if ($serviceResult.Status.ToString() -eq "Running") {
      return $true
    }
  }
  return $false
}

function Test-InstalledSoftwareWMI {
  param (
    [Parameter(Mandatory = $True, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationName
  )
  if (Get-WmiObject -class win32_product | Where-Object name -eq $ApplicationName) {
    return $true
  }
  return $false
}

#This needs to be rewritten not to use += but is still a million times faster and more correct than WMI
function Test-InstalledSoftware {
  [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]

  Param (
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="Global")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndCurrentUser")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndAllUsers")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="CurrentUser")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="AllUsers")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationName,
    [Parameter(ParameterSetName="Global")]
    [switch]$Global,
    [Parameter(ParameterSetName="GlobalAndCurrentUser")]
    [switch]$GlobalAndCurrentUser,
    [Parameter(ParameterSetName="GlobalAndAllUsers")]
    [switch]$GlobalAndAllUsers,
    [Parameter(ParameterSetName="CurrentUser")]
    [switch]$CurrentUser,
    [Parameter(ParameterSetName="AllUsers")]
    [switch]$AllUsers
  )

  # Explicitly set default param to True if used to allow conditionals to work
  if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
    $GlobalAndAllUsers = $true
  }

  # Check if running with Administrative privileges if required
  if ($GlobalAndAllUsers -or $AllUsers) {
    $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($RunningAsAdmin -eq $false) {
      Write-Error "Finding all user applications requires administrative privileges"
      break
    }
  }

  # Empty array to store applications
  $Apps = @()
  $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

  # Retreive globally insatlled applications
  if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
    $Apps += Get-ItemProperty "HKLM:\$32BitPath"
    $Apps += Get-ItemProperty "HKLM:\$64BitPath"
  }

  if ($CurrentUser -or $GlobalAndCurrentUser) {
    $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
    $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
  }

  if ($AllUsers -or $GlobalAndAllUsers) {
    $AllProfiles = Get-CimInstance Win32_UserProfile | 
      Select-Object LocalPath, SID, Loaded, Special | 
      Where-Object {$_.SID -like "S-1-5-21-*"}
    $MountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $true}
    $UnmountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $false}

    $MountedProfiles | Foreach-Object {
      $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
      $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
    }

    $UnmountedProfiles | ForEach-Object {

      $Hive = "$($_.LocalPath)\NTUSER.DAT"

      if (Test-Path $Hive) {
            
        REG LOAD HKU\temp $Hive 2>&1>$null

        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"

        # Run manual GC to allow hive to be unmounted
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
            
        REG UNLOAD HKU\temp 2>&1>$null

      } 
    }
  }

  foreach ($app in $Apps) {
    if ($app.DisplayName -eq $ApplicationName) {
      return $true
    }
  }
  return $false
}

#This needs to be rewritten not to use += but is still a million times faster and more correct than WMI
function Get-UninstallString {
  [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]

  Param (
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="Global")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndCurrentUser")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndAllUsers")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="CurrentUser")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="AllUsers")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="Global32")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndCurrentUser32")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndAllUsers32")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="CurrentUser32")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="AllUsers32")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationName,
    [Parameter(ParameterSetName="Global32")]
    [Parameter(ParameterSetName="GlobalAndCurrentUser32")]
    [Parameter(ParameterSetName="GlobalAndAllUsers32")]
    [Parameter(ParameterSetName="CurrentUser32")]
    [Parameter(ParameterSetName="AllUsers32")]
    [switch]$Wow6432Only,
    [Parameter(ParameterSetName="Global")]
    [Parameter(ParameterSetName="GlobalAndCurrentUser")]
    [Parameter(ParameterSetName="GlobalAndAllUsers")]
    [Parameter(ParameterSetName="CurrentUser")]
    [Parameter(ParameterSetName="AllUsers")]
    [switch]$NoWow6432,
    [Parameter(ParameterSetName="Global")]
    [Parameter(ParameterSetName="Global32")]
    [switch]$Global,
    [Parameter(ParameterSetName="GlobalAndCurrentUser")]
    [Parameter(ParameterSetName="GlobalAndCurrentUser32")]
    [switch]$GlobalAndCurrentUser,
    [Parameter(ParameterSetName="GlobalAndAllUsers")]
    [Parameter(ParameterSetName="GlobalAndAllUsers32")]
    [switch]$GlobalAndAllUsers,
    [Parameter(ParameterSetName="CurrentUser")]
    [Parameter(ParameterSetName="CurrentUser32")]
    [switch]$CurrentUser,
    [Parameter(ParameterSetName="AllUsers")]
    [Parameter(ParameterSetName="AllUsers32")]
    [switch]$AllUsers

  )

  # Explicitly set default param to True if used to allow conditionals to work
  if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
    $GlobalAndAllUsers = $true
  }

  # Check if running with Administrative privileges if required
  if ($GlobalAndAllUsers -or $AllUsers) {
    $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($RunningAsAdmin -eq $false) {
      Write-Error "Finding all user applications requires administrative privileges"
      break
    }
  }

  # Empty array to store applications
  $Apps = @()
  $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

  # Retreive globally installed applications
  if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
    if (!($NoWow6432.IsPresent)) {
      $Apps += Get-ItemProperty "HKLM:\$32BitPath"
    }
    if (!($Wow6432Only.IsPresent)) {
      $Apps += Get-ItemProperty "HKLM:\$64BitPath"
    }
  }

  if ($CurrentUser -or $GlobalAndCurrentUser) {
    if (!($NoWow6432.IsPresent)) {
      $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
    }
    if (!($Wow6432Only.IsPresent)) {
      $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
    }
  }

  if ($AllUsers -or $GlobalAndAllUsers) {
    $AllProfiles = Get-CimInstance Win32_UserProfile | 
      Select-Object LocalPath, SID, Loaded, Special | 
      Where-Object {$_.SID -like "S-1-5-21-*"}
    $MountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $true}
    $UnmountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $false}

    $MountedProfiles | Foreach-Object {
      if (!($NoWow6432.IsPresent)) {
        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
      }
      if (!($Wow6432Only.IsPresent)) {
        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
      }
    }

    $UnmountedProfiles | ForEach-Object {

      $Hive = "$($_.LocalPath)\NTUSER.DAT"

      if (Test-Path $Hive) {
            
        REG LOAD HKU\temp $Hive 2>&1>$null

        if (!($NoWow6432.IsPresent)) {
          $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
        }
        if (!($Wow6432Only.IsPresent)) {
          $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"
        }

        # Run manual GC to allow hive to be unmounted
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
            
        REG UNLOAD HKU\temp 2>&1>$null

      } 
    }
  }

  foreach ($app in $Apps) {
    if ($app.DisplayName -eq $ApplicationName) {
      return $app.UninstallString
    }
  }
  return ""
}

#This needs to be rewritten not to use += but is still a million times faster and more correct than WMI
function Get-ApplicationList {
  [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]

  Param (
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="Global")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndCurrentUser")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndAllUsers")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="CurrentUser")]
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="AllUsers")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationName,
    [Parameter(ParameterSetName="Global")]
    [switch]$Global,
    [Parameter(ParameterSetName="GlobalAndCurrentUser")]
    [switch]$GlobalAndCurrentUser,
    [Parameter(ParameterSetName="GlobalAndAllUsers")]
    [switch]$GlobalAndAllUsers,
    [Parameter(ParameterSetName="CurrentUser")]
    [switch]$CurrentUser,
    [Parameter(ParameterSetName="AllUsers")]
    [switch]$AllUsers
  )

  # Explicitly set default param to True if used to allow conditionals to work
  if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
    $GlobalAndAllUsers = $true
  }

  # Check if running with Administrative privileges if required
  if ($GlobalAndAllUsers -or $AllUsers) {
    $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($RunningAsAdmin -eq $false) {
      Write-Error "Finding all user applications requires administrative privileges"
      break
    }
  }

  # Empty array to store applications
  $Apps = @()
  $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

  # Retreive globally installed applications
  if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
    $Apps += Get-ItemProperty "HKLM:\$32BitPath"
    $Apps += Get-ItemProperty "HKLM:\$64BitPath"
  }

  if ($CurrentUser -or $GlobalAndCurrentUser) {
    $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
    $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
  }

  if ($AllUsers -or $GlobalAndAllUsers) {
    $AllProfiles = Get-CimInstance Win32_UserProfile | 
      Select-Object LocalPath, SID, Loaded, Special | 
      Where-Object {$_.SID -like "S-1-5-21-*"}
    $MountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $true}
    $UnmountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $false}

    $MountedProfiles | Foreach-Object {
      $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
      $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
    }

    $UnmountedProfiles | ForEach-Object {

      $Hive = "$($_.LocalPath)\NTUSER.DAT"

      if (Test-Path $Hive) {
            
        REG LOAD HKU\temp $Hive 2>&1>$null

        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"

        # Run manual GC to allow hive to be unmounted
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
            
        REG UNLOAD HKU\temp 2>&1>$null

      } 
    }
  }

  $returnVal = @()
  foreach ($app in $Apps) {
    if ($app.DisplayName -like "*" + $ApplicationName+ "*") {
      $returnVal += $app.DisplayName
    }
  }
  return $returnVal
}

#Sourced from https://www.remkoweijnen.nl/blog/2013/04/05/convert-bin-to-hex-and-hex-to-bin-in-powershell/
function Convert-BinToHex {
	param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
	  [Byte[]]$Bin)
	# assume pipeline input if we don't have an array (surely there must be a better way)
	if ($Bin.Length -eq 1) {$Bin = @($input)}
	$return = -join ($Bin |  Foreach-Object { "{0:X2}" -f $_ })
	return $return
}
 
#Sourced from https://www.remkoweijnen.nl/blog/2013/04/05/convert-bin-to-hex-and-hex-to-bin-in-powershell/
function Convert-HexToBin {
	param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]	
	  [string]$s
    )
	$return = @()
	
	for ($i = 0; $i -lt $s.Length ; $i += 2)
	{
	$return += [Byte]::Parse($s.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
	}
	
	return $return
}

Function Test-KBInstalled {
  param (
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]	
	  [string]$hotfixID
  )
  $hf = Get-Hotfix "KB$($hotfixID)" -ErrorAction SilentlyContinue
  if ($hf) {
    return $true
  }
  return $false
}

#Sourced from https://stackoverflow.com/questions/28077854/powershell-2-0-convertfrom-json-and-convertto-json-implementation
function ConvertFrom-Json20([object] $item){ 
  add-type -assembly system.web.extensions
  $ps_js=new-object system.web.script.serialization.javascriptSerializer

  #The comma operator is the array construction operator in PowerShell
  return ,$ps_js.DeserializeObject($item)
}

#Sourced from https://stackoverflow.com/questions/28077854/powershell-2-0-convertfrom-json-and-convertto-json-implementation
function ConvertTo-Json20([object] $item){
  add-type -assembly system.web.extensions
  $ps_js=new-object system.web.script.serialization.javascriptSerializer
  return $ps_js.Serialize($item)
}

#Returns a Hashtable with Success, a boolean value and LogMessage, a multi-line string with information about performed operations.
Function Backup-EventLog {
  param (
    [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$eventLogName,
    [switch]$ForceSuccess,
    [switch]$LastHour
  )
  $EVlogMessage = Write-Append "Beginning Export of $($eventLogName) Event Log"
  $targetFile = "$($env:UniversalRMMPath)\$($eventLogName -replace '\W','-')_$(get-date -Format 'yyyyMMddTHHmmss')"
  if ($LastHour.IsPresent) {
    $startTime = Get-Date (Get-Date).AddHours(-1) -Format "yyyy-MM-ddThh:mm:ss"
    $endTime = Get-Date -Format "yyyy-MM-ddThh:mm:ss"
    & wevtutil epl Application /q:"*[System[TimeCreated[@SystemTime>='$($startTime)' and @SystemTime<='$($endTime)']]]" "$($targetFile).evtx"
  } else {
    & wevtutil.exe epl $eventLogName "$($targetFile).evtx"
  }
  if (!(Test-Path "$($targetFile).evtx")) {
    if (!$ForceSuccess.IsPresent) {
      $EVlogMessage += Write-Append "Unable to back up existing $($eventLogName) log file. Aborting."
      return @{Success = $false; LogMessage = $EVlogMessage}
    }
    $EVlogMessage +=Write-Append "Backup of $($eventLogName) was unsuccessful. Force flag detected. Returning Success, even though backup was not successful."
    return @{Success = $true; LogMessage = $EVlogMessage}
  }
  $EVlogMessage += Write-Append "Attempting to compress backed up event log"
  Start-Process "$($env:UniversalRMMPath)\7za.exe" -ArgumentList @("a","$($targetFile).7z","$($targetFile).evtx") -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
  if (Test-Path "$($targetFile).7z") {
    Remove-Item "$($targetFile).evtx" -Force
    $EVlogMessage += Write-Append "Backup of $($eventLogName) was successful."
    return @{ Success = $true; LogMessage = $EVlogMessage}
  } else {
    $EVlogMessage += Write-Append "Backup of $($eventLogName) was successful, but compression of backup was not"
    return @{ Success = $true; LogMessage = $EVlogMessage}
  }
}

#This function assumes that you have placed 7za.exe into the UniversalRMM folder. It is not the most robust way to do this. I don't recommend
#leaning heavily on this function beyond what it's used for here.
Function Compress-7Zip {
  param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$outputFile,
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$source
  )
  
  Start-Process "$($env:UniversalRMMPath)\7za.exe" -ArgumentList @("a",$outputFile,$source) -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
  if (Test-path $outputFile) {
    return $true
  }
  return $false
}

#This function assumes that you have placed 7za.exe into the UniversalRMM folder. It is not the most robust way to do this. I don't recommend
#leaning heavily on this function beyond what it's used for here.
Function Expand-7Zip {
  param (
      [Parameter(Mandatory = $true, Position = 0)]
      [string]$OutputFile,
      [Parameter(Mandatory = $true, Position = 1)]
      [string]$Source
  )
  
  Start-Process "$($env:UniversalRMMPath)\7za.exe" -ArgumentList @("x", "`"$($Source)`"", "-aoa", "-o`"$($OutputFile)`"") -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
  if (Test-path $OutputFile) {
      return $true
  }
  return $false
}

#Sourced and reworked for Powershell 2/Sanity from https://www.powershellgallery.com/packages/Test-PendingReboot/1.11/Content/Test-PendingReboot.ps1
Function Test-RegistryKey {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Key
  )

  if (Get-Item -Path $Key -ErrorAction SilentlyContinue) {
      return $true
  } else {
    return $false
  }
}

#Sourced and reworked for Powershell 2/Sanity from https://www.powershellgallery.com/packages/Test-PendingReboot/1.11/Content/Test-PendingReboot.ps1
Function Test-RegistryValue {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Key,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Value
  )

  if (Get-ItemProperty -Path $Key -Name $Value -ErrorAction SilentlyContinue) {
    return $true
  } else {
    return $false
  }
}

#Sourced and reworked for Powershell 2/Sanity from https://www.powershellgallery.com/packages/Test-PendingReboot/1.11/Content/Test-PendingReboot.ps1
Function Test-RegistryValueNotNull {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Key,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Value
  )

  if (($regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction SilentlyContinue) -and $regVal.($Value)) {
    return $true
  } else {
    return $false
  }
}

#Sourced and reworked for Powershell 2/Sanity from https://www.powershellgallery.com/packages/Test-PendingReboot/1.11/Content/Test-PendingReboot.ps1
Function Test-RebootPending {
$tests = @(
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' }
        { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress' }
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
        { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending' }
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting' }
        { Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations' }
        { Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations2' }
        { 
            # Added test to check first if key exists, using "ErrorAction ignore" will incorrectly return $true
            'HKLM:\SOFTWARE\Microsoft\Updates' | Where-Object { test-path $_ -PathType Container } | ForEach-Object {            
                $a = (Get-ItemProperty -Path $_ -Name 'UpdateExeVolatile' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UpdateExeVolatile)
                if ($a) {$a -ne 0 } else {$false}
            }
        }
        { Test-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Value 'DVDRebootSignal' }
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps' }
        { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'JoinDomain' }
        { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'AvoidSpnSet' }
        {
            # Added test to check first if keys exists, if not each group will return $Null
            # May need to evaluate what it means if one or both of these keys do not exist
            ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' | Where-Object { test-path $_ } | ForEach-Object { (Get-ItemProperty -Path $_ ).ComputerName } ) -ne 
            ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' | Where-Object { Test-Path $_ } | ForEach-Object{ (Get-ItemProperty -Path $_ ).ComputerName } )
        }
        {
            # Added test to check first if key exists
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' | Where-Object { 
                (Test-Path $_) -and (Get-ChildItem -Path $_) } | ForEach-Object { $true }
        }
    )

    foreach ($test in $tests) {
        Write-Verbose "Running scriptblock: [$($test.ToString())]"
        if (& $test) {
            return $true
            break
        }
    }
    return $false
}

function Get-UserFromSID {
    
  param($UserSID = "")

  $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSID) 
  $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
  return $objUser.Value 
  
}

function Get-SIDfromUser {
  
  param($User = "")

  $objUser = New-Object System.Security.Principal.NTAccount($User) 
  $objSID = $objUser.Translate( [System.Security.Principal.SecurityIdentifier]) 
  return $objSID.Value 
  
}

#This is a Datto RMM exclusive function. 
function Write-MonitorResult {
  param (
    [Parameter(Mandatory = $true,Position = 0)]
    [ValidateNotNullOrEmpty()]  
    [string]$OutputResultName,
    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]  
    [string]$Message,
    [Parameter(Position = 2)]
    [string]$DiagnosticMessage
  )
  Write-Host '<-Start Result->'
  Write-Host "$($OutputResultName)=$($Message)"
  Write-Host '<-End Result->'
  if ($DiagnosticMessage) {
    Write-Host '<-Start Diagnostic->'
    Write-Host $DiagnosticMessage
    Write-Host '<-End Diagnostic->'
  }
}

#Code that is executed on import
if (!($env:RMMEventSource)) {
  Write-Error "Environment Variable RMMEventSource must be set to import this module."
  Exit 1
} else {
  #You may set this path to wherever you are loading this module from statically. The module expects 7za.exe to be present in this path.
  $env:UniversalRMMPath = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
  New-RMMEventSource -Source $env:RMMEventSource
}