<#
*********************************** LICENSE ***********************************
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You can view the GNU General Public License at <http://www.gnu.org/licenses/>

WARNING: This program is provided "as-is"
*******************************************************************************
#>

<# 
  .SYNOPSIS
   Extracts different categories of events from DoSvc ETL logs
  .DESCRIPTION
   Extracts different categories of events from DoSvc ETL logs.
   Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
   Win10 1507  | C:\Windows\Logs\dosvc
   Win10 1709+ | C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

   Test environment: (OS) Windows 10 Pro ENG (version 1803/1809/1903/21H1) + Powershell 5.1 + Powershell 7.1
   Script tested against logs collected from:
     - Windows 10 Home x86 ENG (version 1507)
     - Windows 10 Pro  x64 ENG (version 1709/1803/1809/1903/21H1)
     - Windows 10 Pro  x64 ITA (version 1809/1903)
  .PARAMETER DiskInfo
   Extracts the events containing information about computer disk space
  .PARAMETER CaptivePortal
   Extracts all events containing "Captive Portal detected on network"
  .PARAMETER ExternalIP
   Extracts all the external/public IP addresses assigned by an Internet Service Provider (ISP)
  .PARAMETER ExtractAll
   If used, the script will extract DiskInfo + CaptivePortal + ExternalIP + InternalIP + LocalPeers + PowerState + ShutdownTime events. It won't do any geolocation.
  .PARAMETER GeolocationAPI
   Allows to choose among a few APIs. If needed, use -TokenAPI to provide the authorization token.
  .PARAMETER TokenAPI
   Allows to provide the API token for the geolocation service to be used
  .PARAMETER InternalIP
   Extracts all the internal/private IP addresses assigned to the computer
  .PARAMETER LocalPeers
   Extracts the private IP addresses of "PCs on my local network". These events are stored in the ETL logs if the device has the following option turned ON:
   WindowsUpdate | Advanced Option | DeliveryOptimization | Allow downloads from other PCs
  .PARAMETER LogPath
   Path containing the DoSvc .etl files to analyze. LogPath can also be a filename. The script will search recursively by default.
  .PARAMETER OutputPath
   Path where the output files will be written to. By default it's the current working directory.
  .PARAMETER PowerState
   Extracts Battery Status events
  .PARAMETER ShutdownTime
   Extracts Shutdown events (from ETL logs)
  .PARAMETER SkipIP2Location
   If used, the script won't perform any IP geolocation lookup.
  .PARAMETER TimeFormat
   Allows to choose between UTC (default) or LocalTime
  .EXAMPLE
   Get-DoSvc4n6.ps1 dosvc.20181212_133942_927.etl -ExtractAll

   This command parses a single file and extracts events for all categories.
  .EXAMPLE
   Get-DoSvc4n6.ps1 C:\CustomLogPath -ExternalIP -SkipIP2Location -OutputPath C:\CustomOutputPath

   This command recursively parses a path, extracts external/public IP addresses, doesn't do any IP location lookup and saves the output files to a custom path.
  .EXAMPLE
   Get-DoSvc4n6.ps1 C:\CustomLogPath -InternalIP -PowerState -ExternalIP -GeolocationAPI ipwhois -TimeFormat LocalTime

   This command recursively parses a custom path, extracts the events related to the selected categories, uses the ipwhois API and shows timestamps in local time.
  .NOTES
   Author       : Gabriele Zambelli
   Twitter      : @gazambelli

   CHANGELOG
   2021-08-14: [ FIXED ] Minor bug fixes
   2021-08-13: [CHANGED] Removed KeyCDN
               [ FIXED ] ipinfo.io requires a token in the URL
			   [  NEW  ] Added the parameter TokenAPI to provide the needed token
   2019-08-23: [  NEW  ] Added compatibility for Google Timesketch
               [  NEW  ] Added new switches to extract more data: 
                         DiskInfo, CaptivePortal, ExternalIP, InternalIP, LocalPeers, PowerState, ShutdownTime, ExtractAll
               [  NEW  ] New switch GeolocationAPI to select which geolocation API to use among the ones supported by the script
               [  NEW  ] Timestamps can now be shown in UTC or local time
               [  NEW  ] Added support for Windows 10 1903
               [ FIXED ] Added new condition to avoid extracting "ExternalIP" false positive results
               [CHANGED] The script requires PS Version >=5 with DeliveryOptimization module
               [CHANGED] The script was renamed to Get-DoSvc4n6
               [CHANGED] "NoIP2Location" switch renamed to "SkipIP2Location"
   2019-04-05: Added switch -SkipIP2Location, parameter -OutputPath and "isVpn" column
               Minor improvements
   2019-04-03: Added progress bars and a warning message
   2019-01-31: Fixed compatibility issues with Win10 1809 ETL logs which 
               may contain more than one "ExternalIpAddress" per file
   2018-12-05: First release
  .LINK
   GitHub     : https://github.com/forensenellanebbia
   Blog post  : https://forensenellanebbia.blogspot.it/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html
   DFIR Review: https://dfir.pubpub.org/pub/httnwst7
#>

#requires -Version 5

[CmdletBinding()]
Param (
[Parameter(Mandatory=$false,Position=0)][string]$LogPath,
[switch]$DiskInfo,
[switch]$CaptivePortal,
[switch]$ExternalIP,
[switch]$InternalIP,
[switch]$LocalPeers,
[switch]$PowerState,
[switch]$ShutdownTime,
[switch]$ExtractAll,
[ValidateSet("ipwhois","ipinfo","ip-api")][string]$GeolocationAPI,
[Parameter(Mandatory=$false)][string]$TokenAPI,
[switch]$SkipIP2Location,
[ValidateSet("UTC","LocalTime")][string]$TimeFormat,
[Parameter(Mandatory=$false)][string]$OutputPath
)

<#
    Microsoft Get-DeliveryOptimizationLog cmdlet retrieves and parses DeliveryOptimization logs.
    Cmdlet available since Windows 10 Insider Preview Build 17074:
    https://blogs.windows.com/windowsexperience/2018/01/11/announcing-windows-10-insider-preview-build-17074-pc/

    Check out these guides on the meaning of the various diagnostic fields:
    https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1703.md
    https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1709.md
    https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803.md
    https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1809.md
    https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1903.md

    Windows Update Delivery Optimization and privacy
    https://support.microsoft.com/en-us/help/4468254/windows-update-delivery-optimization-faq
#>

$CheckDeliveryOptimizationModule = Get-Module -ListAvailable -Name DeliveryOptimization
if(-Not ($CheckDeliveryOptimizationModule))
    {
        Write-Host "`nERROR: DeliveryOptimization module is NOT installed`n" -ForegroundColor Yellow
        break
    }

#region script title
$script_version = "2021-08-14"
$script_name    = "Get-DoSvc4n6"

#http://www.patorjk.com/software/taag/#p=display&f=Big&t=Get-DoSvc4n6
$script_title   = @"
 _____       _          _____        _____          _  _           __  
/ ____|     | |        |  __ \      / ____|        | || |         / /  
| |  __  ___| |_ ______| |  | | ___| (_____   _____| || |_ _ __  / /_  
| | |_ |/ _ \ __|______| |  | |/ _ \\___ \ \ / / __|__   _| '_ \| '_ \ 
| |__| |  __/ |_       | |__| | (_) |___) \ V / (__   | | | | | | (_) |
 \_____|\___|\__|      |_____/ \___/_____/ \_/ \___|  |_| |_| |_|\___/ 
"@

Write-Host "`n$script_title`n(v.$script_version)`r`n`nAuthor: Gabriele Zambelli @gazambelli`nhttps://github.com/forensenellanebbia`n" -ForegroundColor Cyan
#endregion script title

#region functions
function Set-Filenames ($TimeFormatLabel)
    {
        $OutputPath + "\" + $ScriptStartedDateTime + "_TS-" + $TimeFormatLabel + "_DoSvc_" + $SwitchLabel + ".csv"
        $OutputPath + "\" + $ScriptStartedDateTime + "_TS-" + $TimeFormatLabel + "_DoSvc_" + $SwitchLabel + ".json"
    }

function Write-ToFile ($ParameterOutput, $File_csv)
    {
        if(Test-Path $File_csv)
            {
                $ParameterOutput = $ParameterOutput | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
                Add-Content $File_csv -Value $ParameterOutput
            }
        else
            {
                $ParameterOutput | Export-Csv $File_csv -NoTypeInformation    
            }
    }

function Write-APIResponseToFile ($IpProgressCounter, $IpCount, $ApiResponse, $FileExtIP2Loc_json)
    {
        if ($IpProgressCounter -lt $IpCount)
            {
                $ApiResponse = $ApiResponse + ","
            }
        Add-Content $FileExtIP2Loc_json -Value $ApiResponse
        Start-Sleep -Seconds 3 #Waiting time between API calls        
    }

function Show-Results ($File_csv, $KeyCategory)
    {
        if($null -eq $File_csv)
            {
                $File_csv = "temporary.idontexist"
            }
        if(Test-Path $File_csv)
            {
                $rows = (Import-Csv $File_csv | Measure-Object).Count
                $text = "[+] $KeyCategory"
            }
        else 
            {
                $rows = 0
                $text = "[-] $KeyCategory"
            }
        $text = $text + " " * (18 - $text.length) + ": "
        Write-Host $text $rows
    }
#endregion functions

if($LogPath -and ($PSBoundParameters.Count -ge 2) -and ($PSBoundParameters.ContainsKey('DiskInfo') -or $PSBoundParameters.ContainsKey('CaptivePortal') -or $PSBoundParameters.ContainsKey('ExternalIP') -or $PSBoundParameters.ContainsKey('InternalIP') -or $PSBoundParameters.ContainsKey('LocalPeers') -or $PSBoundParameters.ContainsKey('PowerState') -or $PSBoundParameters.ContainsKey('ShutdownTime') -or $PSBoundParameters.ContainsKey('ExtractAll') -or $PSBoundParameters.ContainsKey('TokenAPI')))
    {
        $InitialDateTime = Get-Date
        $ScriptStartedDateTime = $InitialDateTime | Get-Date -Format "yyyyMMdd_HHmmss"

        #region check parameters
        if($PSBoundParameters.ContainsKey('ExtractAll'))
            {
                if(-Not ($PSBoundParameters.ContainsKey('DiskInfo') -or $PSBoundParameters.ContainsKey('CaptivePortal') -or $PSBoundParameters.ContainsKey('ExternalIP') -or $PSBoundParameters.ContainsKey('InternalIP') -or $PSBoundParameters.ContainsKey('LocalPeers') -or $PSBoundParameters.ContainsKey('PowerState') -or $PSBoundParameters.ContainsKey('ShutdownTime')))
                    {
                    $PSBoundParameters.Add('DiskInfo','True')
                    $PSBoundParameters.Add('CaptivePortal','True')
                    $PSBoundParameters.Add('ExternalIP','True')
                    $PSBoundParameters.Add('InternalIP','True')
                    $PSBoundParameters.Add('LocalPeers','True')
                    $PSBoundParameters.Add('PowerState','True')
                    $PSBoundParameters.Add('ShutdownTime','True')
                    }
                else
                    {
                        Write-Host "`nWARNING: ExtractAll is not compatible with the selected parameters`n" -ForegroundColor Yellow
                        Write-Host "Script started: $($InitialDateTime | Get-Date -Format "yyyy-MM-dd HH:mm:ss")"
                        Write-Host "Script ended  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`n"
                        break
                    }
            }

        if($PSBoundParameters.ContainsKey('OutputPath'))
            {
                if(Test-Path $OutputPath)
                    {
                        $OutputPath = $OutputPath -replace "\\$" #remove trailing backslash
                    }
                else
                    {
                        throw "The output path doesn't exist."
                    }
            }
        else
            {
                $OutputPath = Get-Location | Select-Object -ExpandProperty Path
            }
        #endregion check parameters

        #region ETL parsing
        $ETLs = Get-ChildItem $LogPath -File -Include ("domgmt*.etl", "dosvc*.etl") -Recurse | Sort-Object Name
        if($ETLs)
            {
                Write-Host "[+] DoSvc ETL files found: $($ETLs.Count)" -ForegroundColor Green
                $EtlProgressCounter = 0 #counter
                foreach($ETL in $ETLs)
                    {
                        $EtlProgressCounter++
                        Write-Progress -Activity "Processing Event Trace Log (.etl) files:" -Status "Processing $($EtlProgressCounter) of $($ETLs.Count)" -CurrentOperation $ETL
                        #Decode logs + add a column named LogName which contains the name and path of the log file
                        $GetDeliveryOptmizationLogOutput = Get-DeliveryOptimizationLog -Path $ETL.FullName | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name LogName -Value $ETL.Name -PassThru}
                        $GetDeliveryOptmizationLogOutput = $GetDeliveryOptmizationLogOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name LogPath -Value $ETL.DirectoryName -PassThru}

                        if($GetDeliveryOptmizationLogOutput)
                            {
                                if($PSBoundParameters.ContainsValue("LocalTime"))
                                    {
                                        $GetDeliveryOptmizationLogOutput = $GetDeliveryOptmizationLogOutput | Select-Object LogName,LogPath,@{N="TimeCreated";E={$_.TimeCreated.ToLocalTime()}},ProcessId,ThreadId,Level,LevelName,Message,Function,LineNumber,ErrorCode
                                        #local time - add Datetime ISO8601 format field
                                        $GetDeliveryOptmizationLogOutput = $GetDeliveryOptmizationLogOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name datetime -Value (get-date $_.TimeCreated.ToLocalTime() -Format "o") -PassThru}
                                        #local time - add Unix timestamp (nanoseconds)
                                        $GetDeliveryOptmizationLogOutput = $GetDeliveryOptmizationLogOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp -Value ([int64]((get-date $_.TimeCreated)-(get-date "1/1/1970")).Totalmilliseconds) -PassThru}
                                        $TimeFormatLabel = "LT"
                                    }
                                else
                                    {
                                        #UTC - add Datetime ISO8601 format field
                                        $GetDeliveryOptmizationLogOutput = $GetDeliveryOptmizationLogOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name datetime -Value (get-date $_.TimeCreated -Format "o") -PassThru}
                                        #UTC - add Unix timestamp (nanoseconds)
                                        $GetDeliveryOptmizationLogOutput = $GetDeliveryOptmizationLogOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp -Value ([int64]((get-date $_.TimeCreated)-(get-date "1/1/1970")).Totalmilliseconds) -PassThru}
                                        $TimeFormatLabel = "UTC" #timestamps are shown by default in UTC
                                    }


                                if($PSBoundParameters.ContainsKey('CaptivePortal'))
                                    {
                                        $SwitchLabel = "CaptivePortal"
                                        $FileCaptivePortal_csv, $FileCaptivePortal_json = Set-Filenames $TimeFormatLabel

                                        $CaptivePortalOutput = $GetDeliveryOptmizationLogOutput | Where-Object {($_.Function -Like "*::IsNetworkConnectivityPresent") -and ($_.Message -like "*Captive Portal*")}
                                        $CaptivePortalOutput = $CaptivePortalOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "CaptivePortal" -PassThru}
                                        $CaptivePortalOutput = $CaptivePortalOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name Network -Value "" -PassThru}
                                        if($CaptivePortalOutput)
                                            {
                                                <#
                                                timesketch: example CSV file
                                                message,timestamp,datetime,timestamp_desc,extra_field_1,extra_field_2
                                                A message,1331698658276340,2015-07-24T19:01:01+00:00,Write time,foo,bar
                                                https://github.com/google/timesketch/blob/master/docs/CreateTimelineFromJSONorCSV.md
                                                #>
                                                $CaptivePortalOutput = $CaptivePortalOutput | Select-Object @{N="message";E={"[Captive Portal] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,@{N="Network";E={($_.Message -replace "Captive Portal detected on network ","" -replace "'","")}},ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                Write-ToFile $CaptivePortalOutput $FileCaptivePortal_csv
                                            }
                                    }

                                if($PSBoundParameters.ContainsKey('DiskInfo'))
                                    {
                                        $SwitchLabel = "DiskInfo"
                                        $FileDiskInfo_csv, $FileDiskInfo_json = Set-Filenames $TimeFormatLabel

                                        $DiskInfoOutput = $GetDeliveryOptmizationLogOutput | Where-Object {($_.Function -Like "*::_IsDownloadEnabledPerDiskTotalSize") -or ($_.Function -like "*::TracePerfSnap")}
                                        $DiskInfoOutput = $DiskInfoOutput | Where-Object {($_.Message -Like "*disk*")}
                                        $DiskInfoOutput = $DiskInfoOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "DiskInfo" -PassThru}
                                        $DiskInfoOutput = $DiskInfoOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name totalDiskSize -Value "" -PassThru}
                                        $DiskInfoOutput = $DiskInfoOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name freeDiskSpace -Value "" -PassThru}
                                        $DiskInfoOutput = $DiskInfoOutput | Select-Object @{N="message";E={$_.Message -replace ".*totalDiskSize","totalDiskSize" -replace "PERF.*disk:","disk:" -replace ", peers.*",""}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode

                                        if($DiskInfoOutput)
                                            {
                                                foreach($DiskInfoEvent in $DiskInfoOutput)
                                                    {
                                                        if($DiskInfoEvent.message -like "*totalDiskSize*")
                                                            {
                                                                $DiskInfoEvent = $DiskInfoEvent | Select-Object Message,timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,@{N="totalDiskSize";E={$DiskInfoEvent.message -replace "totalDiskSize = ",""}},freeDiskSpace,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        if($DiskInfoEvent.message -like "disk:*")
                                                            {
                                                                $DiskInfoEventMessageJson = $DiskInfoEvent.message -replace "disk:","" -replace "\[","{" -replace "\]","}" | ConvertFrom-Json
                                                                $DiskInfoEventtotalDiskSize = [math]::Round($DiskInfoEventMessageJson.total/1024/1024/1024,2)
                                                                $DiskInfoEventtotalDiskSize = $DiskInfoEventtotalDiskSize.ToString() + " GB ($($DiskInfoEventMessageJson.total) Bytes)"
                                                                $DiskInfoEvent = $DiskInfoEvent | Select-Object Message,timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,@{N="totalDiskSize";E={$DiskInfoEventtotalDiskSize}},freeDiskSpace,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                                $DiskInfoEventfreeDiskSpace = [math]::Round($DiskInfoEventMessageJson.free/1024/1024,0)
                                                                $DiskInfoEventfreeDiskSpace = $DiskInfoEventfreeDiskSpace.ToString() + " MB ($($DiskInfoEventMessageJson.free) Bytes)"
                                                                $DiskInfoEvent = $DiskInfoEvent | Select-Object Message,timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,totalDiskSize,@{N="freeDiskSpace";E={$DiskInfoEventfreeDiskSpace}},ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        
                                                        if($null -eq $DiskInfoEvent.freeDiskSpace)
                                                            {
                                                                $DiskInfoEvent = $DiskInfoEvent | Select-Object @{N="message";E={"[Disk Information] totalDiskSize: " + $_.totalDiskSize}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,totalDiskSize,freeDiskSpace,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        else
                                                            {
                                                                $DiskInfoEvent = $DiskInfoEvent | Select-Object @{N="message";E={"[Disk Information] totalDiskSize: " + $_.totalDiskSize + ", freeDiskSpace: " + $_.freeDiskSpace}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,totalDiskSize,freeDiskSpace,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        Write-ToFile $DiskInfoEvent $FileDiskInfo_csv        
                                                    }
                                            }
                                    }

                                if($PSBoundParameters.ContainsKey('InternalIP'))
                                    {
                                        $SwitchLabel = "InternalIP"
                                        $FileInternalIP_csv, $FileInternalIP_json = Set-Filenames $TimeFormatLabel

                                        $InternalIPOutput = $GetDeliveryOptmizationLogOutput | Where-Object {($_.Function -like "*::_InternalAnnounce") -and ($_.Message -like "*ReportedIp*")}
                                        $InternalIPOutput = $InternalIPOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "InternalIP" -PassThru}
                                        $InternalIPOutput = $InternalIPOutput | Select-Object @{N="message";E={$_.Message -replace "Swarm.*announce request:",""}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode	
                                        $InternalIPOutput = $InternalIPOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name InternalIp -Value (($_.Message | ConvertFrom-Json).ReportedIp) -PassThru}
                                        $InternalIPOutput = $InternalIPOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name SubnetMask -Value (($_.Message | ConvertFrom-Json).SubnetMask) -PassThru}
                                        $InternalIPOutput = $InternalIPOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name Ipv6 -Value (($_.Message | ConvertFrom-Json).Ipv6) -PassThru}
                                        $InternalIPOutput = $InternalIPOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name ClientCompactVersion -Value (($_.Message | ConvertFrom-Json).ClientCompactVersion) -PassThru}
                                        
                                        if($InternalIPOutput)
                                            {
                                                if($null -eq $_.Ipv6)
                                                    {
                                                        $InternalIPOutput = $InternalIPOutput | Select-Object @{N="message";E={"[Private IP] IP: " + $_.InternalIP + ", Subnet Mask: " + $_.SubnetMask}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,InternalIP,SubnetMask,Ipv6,ClientCompactVersion,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode	
                                                    }
                                                else
                                                    {
                                                        $InternalIPOutput = $InternalIPOutput | Select-Object @{N="message";E={"[Private IP] IP: " + $_.InternalIP + ", Subnet Mask: " + $_.SubnetMask + ", Ipv6: " + $_.Ipv6}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,InternalIP,SubnetMask,Ipv6,ClientCompactVersion,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode	
                                                    }
                                                Write-ToFile $InternalIPOutput $FileInternalIP_csv
                                            }
                                    }

                                if($PSBoundParameters.ContainsKey('LocalPeers'))
                                    {
                                        $SwitchLabel = "LocalPeers"
                                        $FileLocalPeers_csv, $FileLocalPeers_json = Set-Filenames $TimeFormatLabel

                                        $LocalPeersOutput = $GetDeliveryOptmizationLogOutput | Where-Object {($_.Function -like "*::ConnectionComplete") -and ($_.Message -match "(\[192\.168\.)|(\[10\.)|(\[172\.1[6-9]\.)|(\[172\.2[0-9]\.)|(\[172\.3[0-1]\.)")}
                                        $LocalPeersOutput = $LocalPeersOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "LocalPeers" -PassThru}
                                        if($LocalPeersOutput)
                                            {
                                                $LocalPeersOutput = $LocalPeersOutput | Select-Object @{N="message";E={"[PC on local network] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                Write-ToFile $LocalPeersOutput $FileLocalPeers_csv
                                            }
                                    }

                                if($PSBoundParameters.ContainsKey('PowerState'))
                                    {
                                        $SwitchLabel = "PowerState"
                                        $FilePowerState_csv, $FilePowerState_json = Set-Filenames $TimeFormatLabel

                                        $PowerStateOutput = $GetDeliveryOptmizationLogOutput | Where-Object {($_.Message -like "*battery*") -or ($_.Message -like "*power state*") -or ($_.Message -like "*power status*")}
                                        $PowerStateOutput = $PowerStateOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "PowerState" -PassThru}
                                        if($PowerStateOutput)
                                            {
                                                foreach($PowerStateEvent in $PowerStateOutput)
                                                    {
                                                        if(($PowerStateEvent.Message -like "*battery? 1*") -or ($PowerStateEvent.Message -like "*power status = 0*") -or ($PowerStateEvent.Message -like "*low battery*"))
                                                            {
                                                                $PowerStateEvent = $PowerStateEvent | Select-Object @{N="message";E={"[Power mode: unplugged] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        elseif(($PowerStateEvent.Message -like "*battery? 0*") -or ($PowerStateEvent.Message -like "*power status = 1*"))
                                                            {
                                                                $PowerStateEvent = $PowerStateEvent | Select-Object @{N="message";E={"[Power mode: plugged in] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        elseif($PowerStateEvent.Message -like "*battery level*")
                                                            {
                                                                $PowerStateEvent = $PowerStateEvent | Select-Object @{N="message";E={"[Battery level] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        else
                                                            {
                                                                $PowerStateEvent = $PowerStateEvent | Select-Object @{N="message";E={"[Power state] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        Write-ToFile $PowerStateEvent $FilePowerState_csv
                                                    }
                                            }
                                    }

                                if($PSBoundParameters.ContainsKey('ShutdownTime'))
                                    {
                                        $SwitchLabel = "ShutdownTime"
                                        $FileShutdownTime_csv, $FileShutdownTime_json = Set-Filenames $TimeFormatLabel

                                        $ShutdownTimeOutput = $GetDeliveryOptmizationLogOutput | Where-Object {($_.Message -match "system shutdown. 1") -or ($_.Message -like "*sleep/hibernation state*")}
                                        $ShutdownTimeOutput = $ShutdownTimeOutput | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "ShutdownTime" -PassThru}
                                        if($ShutdownTimeOutput)
                                            {
                                                foreach($ShutdownTimeEvent in $ShutdownTimeOutput)
                                                    {
                                                        if($ShutdownTimeEvent.Message -match "system shutdown. 1")
                                                            {
                                                                $ShutdownTimeEvent = $ShutdownTimeEvent | Select-Object @{N="message";E={"[System Restart/Shutdown] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        else
                                                            {
                                                                $ShutdownTimeEvent = $ShutdownTimeEvent | Select-Object @{N="message";E={"[Sleep/Hibernation] " + $_.Message}},timestamp,datetime,timestamp_desc,LogName,LogPath,TimeCreated,ProcessId,ThreadId,Level,LevelName,Function,LineNumber,ErrorCode
                                                            }
                                                        Write-ToFile $ShutdownTimeEvent $FileShutdownTime_csv
                                                    }
                                            }
                                    }

                                if($PSBoundParameters.ContainsKey('ExternalIP'))
                                    {
                                        $SwitchLabel = "ExternalIP"
                                        $FileExternalIP_csv, $FileExternalIP_json = Set-Filenames $TimeFormatLabel
                        
                                        #region isVpn
                                        $search_isVpn = $GetDeliveryOptmizationLogOutput | Select-Object TimeCreated,ProcessId,ThreadId,Message | Where-Object {($_.Message -Like "*Detected connected VPN adapter*")}
                                        if($search_isVpn)
                                            {
                                                $search_isVpn = $search_isVpn | Select-Object @{name="TimeCreated";expression={$_.TimeCreated.ToString("yyyy-MM-dd HH:mm")}},ProcessId,ThreadId,Message
                                                $search_isVpn = $search_isVpn | Select-Object TimeCreated,ProcessId,ThreadId,@{name="isVpn";expression={$_.Message}} | Sort-Object TimeCreated -Unique
                                            }
                                        #endregion isVpn

                                        #region GeoResponse
                                        $search_ip = $GetDeliveryOptmizationLogOutput | Where-Object {(($_.Function -eq "CGeoInfoProvider::RefreshConfigs") -or ($_.Function -eq "CServiceConfigProvider::_CallService")) -and ($_.Message -match "GEO(:)? response:")}
                                        $search_ip = $search_ip | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name timestamp_desc -Value "ExternalIP" -PassThru}
                                        if($search_ip)
                                            {
                                                foreach($IP in $search_ip) #ETL files may contain more than one "GEO: response:" value 
                                                    {
                                                        $messageJSON = "[" + ($IP.Message -replace ".*{","{") + "]"
                                                        $messageCSV = ($messageJSON | ConvertFrom-Json) | Select-Object ExternalIpAddress,CountryCode,KeyValue_EndpointFullUri,Version,CompactVersion,isVpn | ConvertTo-Csv -NoTypeInformation
                                                        #Add new member "ExternalIpAddress"
                                                        $IP = $IP | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name ExternalIpAddress -Value ($messageCSV | ConvertFrom-Csv).ExternalIpAddress -PassThru}
                                                        #Add new member "CountryCode"
                                                        $IP = $IP | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name CountryCode -Value ($messageCSV | ConvertFrom-Csv).CountryCode -PassThru}
                                                        #Add new member "KeyValue_EndpointFullUri"
                                                        $IP = $IP | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name KeyValue_EndpointFullUri -Value ($messageCSV | ConvertFrom-Csv).KeyValue_EndpointFullUri -PassThru}
                                                        #Add new member "Version"
                                                        $IP = $IP | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name Version -Value ($messageCSV | ConvertFrom-Csv).Version -PassThru}
                                                        #Add new member "CompactVersion"
                                                        $IP = $IP | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name CompactVersion -Value ($messageCSV | ConvertFrom-Csv).CompactVersion -PassThru}
                                                        #Change the order of the objects
                                                        $IP = $IP | Select-Object @{N="message";E={"[Public IP] IP: " + $_.ExternalIpAddress + ", CountryCode: " + $_.CountryCode}},timestamp,datetime,timestamp_desc,LogName,LogPath,@{name="TimeCreated";expression={$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")}},ExternalIpAddress,isVpn,CountryCode,KeyValue_EndpointFullUri,Version,CompactVersion,ProcessId,ThreadId,Level,LevelName,Function,LineNumber
                                                        
                                                        if($search_isVpn)
                                                            {
                                                                foreach($isVpn in $search_isVpn)
                                                                    {
                                                                        <#Compare timestamps of isVpn and ExternalIp events; if the two values are close to each other, and if the two events
                                                                        belong to the same ProcessId, then that ExternalIP was assigned when using a VPN.#>
                                                                        if($isVpn.TimeCreated.Substring(0,15) -eq $IP.TimeCreated.Substring(0,15) -and $isVpn.ProcessId -eq $IP.ProcessId)
                                                                            {
                                                                                $IP.isVpn = $isVpn.isVpn
                                                                            }
                                                                    }
                                                            }
                                                                                                                
                                                        Write-ToFile $IP $FileExternalIP_csv

                                                    }
                                            }
                                    }
                                        #endregion GeoResponse
                            }
                    }
                
                #region Summary_ExceptExternalIP
                Write-Host "`nEvents found per category"
                if($PSBoundParameters.ContainsKey('CaptivePortal')) { Show-Results $FileCaptivePortal_csv CaptivePortal }
                if($PSBoundParameters.ContainsKey('DiskInfo')) { Show-Results $FileDiskInfo_csv DiskInfo }
                if($PSBoundParameters.ContainsKey('ExternalIP')) { Show-Results $FileExternalIP_csv ExternalIP }
                if($PSBoundParameters.ContainsKey('InternalIP')) { Show-Results $FileInternalIP_csv InternalIP }
                if($PSBoundParameters.ContainsKey('LocalPeers')) { Show-Results $FileLocalPeers_csv LocalPeers }
                if($PSBoundParameters.ContainsKey('PowerState')) { Show-Results $FilePowerState_csv PowerState }
                if($PSBoundParameters.ContainsKey('ShutdownTime')) { Show-Results $FileShutdownTime_csv ShutdownTime }
                Write-Host "`n"
                #endregion Summary_ExceptExternalIP

                #region Summary_ExternalIP
                if($PSBoundParameters.ContainsKey('ExternalIP'))
                    {
                        if(($null -ne $FileExternalIP_csv) -and (Test-Path $FileExternalIP_csv))
                            {
                                #ExternalIP JSON OUTPUT
                                $FileExternalIP_csv_input = Import-Csv $FileExternalIP_csv
                                $FileExternalIP_csv_input | ConvertTo-Json | Out-File $FileExternalIP_json -Encoding utf8

                                $IP_uniq = $FileExternalIP_csv_input | Select-Object ExternalIpAddress -unique #get unique IP addresses
                                $IP_uniq = ($IP_uniq | Select-Object -ExpandProperty ExternalIpAddress) | Sort-Object { [version]$_ } #sort by IP address

                                Write-Host "[+] Unique ExternalIP(s) found: $($IP_uniq.count)" -ForegroundColor Green

                                if($PSBoundParameters.ContainsKey('SkipIP2Location'))
                                    {
                                        #SUMMARY: Display number of occurrences per unique IP address
                                        Write-Host "`nNumber of occurrences per unique ExternalIP:"
                                        $FileExternalIP_csv_input | Group-Object ExternalIpAddress -NoElement | Sort-Object { [version]$_.Name } | Select-Object Count, @{N="ExternalIP";E={$_.Name}} | Format-Table
                                    }
                                else
                                    {
                                        #region GeolocationAPI
                                        if($PSBoundParameters.ContainsValue('ipwhois'))
                                            {
                                                $SwitchLabel = "IP2Location-API_ipwhois"    
                                            }
                                        elseif($PSBoundParameters.ContainsValue('ipinfo'))
                                            {
                                                $SwitchLabel = "IP2Location-API_ipinfo"    
                                            }
                                        else
                                            {
                                                $SwitchLabel = "IP2Location-API_ip-api"
                                            }

                                        $FileExtIP2Loc_csv, $FileExtIP2Loc_json = Set-Filenames $TimeFormatLabel

                                        Add-Content $FileExtIP2Loc_json -Value "["
                                        $IpProgressCounter = 0
                                        foreach($IP in $IP_uniq)
                                            {
                                                $IpProgressCounter++
                                                if($PSBoundParameters.ContainsValue('ipwhois'))
                                                    {
                                                        Write-Progress -Activity "Performing IP location lookup using ipwhois API:" -Status "Processing $($IpProgressCounter) of $($IP_uniq.Count)" -CurrentOperation $IP
                                                        $Ip2LocUrl = "http://free.ipwhois.io/json/" + $IP #https://ipwhois.io/documentation
                                                        $ApiResponse = (Invoke-WebRequest $Ip2LocUrl).Content
                                                        Write-APIResponseToFile $IpProgressCounter $IP_uniq.Count $ApiResponse $FileExtIP2Loc_json
                                                    }
                                                elseif($PSBoundParameters.ContainsValue('ipinfo'))
                                                    {
                                                        Write-Progress -Activity "Performing IP location lookup using ipinfo API:" -Status "Processing $($IpProgressCounter) of $($IP_uniq.Count)" -CurrentOperation $IP
                                                        $Ip2LocUrl = "https://ipinfo.io/" + $IP + "?token=" + $TokenAPI #https://ipinfo.io/developers
                                                        $ApiResponse = (Invoke-WebRequest $Ip2LocUrl).Content
                                                        Write-APIResponseToFile $IpProgressCounter $IP_uniq.Count $ApiResponse $FileExtIP2Loc_json
                                                    }
                                                else
                                                    {
                                                        Write-Progress -Activity "Performing IP location lookup using ip-api API:" -Status "Processing $($IpProgressCounter) of $($IP_uniq.Count)" -CurrentOperation $IP
                                                        $Ip2LocUrl = "http://ip-api.com/json/" + $IP #http://ip-api.com/docs/api:json
                                                        $ApiResponse = (Invoke-WebRequest $Ip2LocUrl).Content
                                                        Write-APIResponseToFile $IpProgressCounter $IP_uniq.Count $ApiResponse $FileExtIP2Loc_json
                                                    }
                                            }
                                        Add-Content $FileExtIP2Loc_json -Value "]"
                                        (Get-Content $FileExtIP2Loc_json | ConvertFrom-Json) | Export-Csv $FileExtIP2Loc_csv -NoTypeInformation
                                        #endregion GeolocationAPI

                                        #SUMMARY: show unique IP addresses found
                                        Write-Host "`nWarning: IP geolocation data could be inaccurate and should be treated with caution" -ForegroundColor Red -BackgroundColor White
                                        $IP2Loc = (Get-Content $FileExtIP2Loc_json | ConvertFrom-Json)
                                        if($PSBoundParameters.ContainsValue('ipwhois'))
                                            {
                                                <#Fields in the response:
                                                ip,success,type,continent,continent_code,country,country_code,country_flag,country_capital,country_phone,
                                                country_neighbours,region,city,latitude,longitude,asn,org,isp,timezone,timezone_name,timezone_dstOffset,
                                                timezone_gmtOffset,timezone_gmt,currency,currency_code,currency_symbol,currency_rates,currency_plural
                                                #>
                                                $IP2Loc | Select-Object  @{Name="ExternalIp";Expression={$_.ip}},asn,isp,city,country_code | Format-Table -AutoSize        
                                            }
                                        elseif($PSBoundParameters.ContainsValue('ipinfo'))
                                            {
                                                #Fields in the response: ip,hostname,anycast,city,region,country,loc,org,postal,timezone
                                                $IP2Loc | Select-Object  @{Name="ExternalIp";Expression={$_.ip}},org,city,country | Format-Table -AutoSize        
                                            }
                                        else
                                            {
                                                #Fields in the response: as,city,country,countryCode,isp,lat,lon,org,query,region,regionName,status,timezone,zip
                                                $IP2Loc | Select-Object  @{Name="ExternalIp";Expression={$_.query}},isp,city,countrycode | Format-Table -AutoSize    
                                            }
                                    }
                            }
                    }
                #endregion Summary_ExternalIP

                Write-Host "Done!`n"
            }
        else
            {
                Write-Host "[-] DoSvc ETL files found: $($ETLs.Count)`n" -ForegroundColor Yellow
            }
        #endregion ETL parsing

        Write-Host "Script started: $($InitialDateTime | Get-Date -Format "yyyy-MM-dd HH:mm:ss")"
        Write-Host "Script ended  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`n"
    }
else
    {
        Write-Host "The script extracts different categories of events from DoSvc ETL logs. Use Get-Help for more details."

        Write-Host "`nWARNING: Not enough parameters provided." -ForegroundColor Yellow
        Write-Host "`nExamples:"
        Write-Host ".\$script_name.ps1 dosvc.20181212_133942_927.etl -ExtractAll"
        Write-Host ".\$script_name.ps1 C:\CustomLogPath -ExternalIP -SkipIP2Location -OutputPath C:\CustomOutputPath"
        Write-Host ".\$script_name.ps1 C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs -DiskInfo`n"
    }