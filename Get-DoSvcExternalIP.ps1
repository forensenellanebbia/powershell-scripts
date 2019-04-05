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
   Extracts external/public IP addresses from DoSvc ETL logs and performs an IP Address Lookup
  .DESCRIPTION
   Extracts external/public IP addresses from DoSvc ETL logs and performs an IP Address Lookup by using the "ip-api" API.
   Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
   Win10 1507  | C:\Windows\Logs\dosvc
   Win10 1709+ | C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

   Test environment: (OS) Windows 10 Pro ENG (version 1803/1809) + Powershell 5.1
   Script tested against logs collected from:
     - Windows 10 Home x86 ENG (version 1507)
     - Windows 10 Pro x64 ENG  (version 1709/1803/1809)

   Windows 10 keeps track of VPN usage on the device. If a VPN was used, the following strings are recorded in the logs:
     - Detected connected VPN adapter
     - Network connectivity: vpn_connected? 1
     - isVpn: 1
   Vpn events don't have "ExternalIpAddress" in the Message field, and vice versa.
   The script compares the fields "ProcessId" and "TimeCreated" to put things together.
  .PARAMETER LogPath
   Path containing the .etl files to analyze. LogPath can also be a filename.
  .PARAMETER NoIP2Location
   If used, the script won't perform any IP location lookup.
  .PARAMETER OutputPath
   Path where the output files will be written to. By default it's the current working directory.
  .EXAMPLE
   Get-DoSvcExternalIP.ps1 C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

   This command recursively parses a path.
  .EXAMPLE
   Get-DoSvcExternalIP.ps1 dosvc.20181212_133942_927.etl

   This command parses a file.
  .EXAMPLE
   Get-DoSvcExternalIP.ps1 C:\CustomLogPath -NoIP2Location -OutputPath C:\CustomOutputPath

   This command recursively parses a path, doesn't do any IP location lookup and saves the output files to a custom path.
  .NOTES
   Author       : Gabriele Zambelli
   Twitter      : @gazambelli
   GitHub       : https://github.com/forensenellanebbia
   Blog post    : https://forensenellanebbia.blogspot.it/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html
   DFIR Review  : https://dfir.pubpub.org/pub/httnwst7

   CHANGELOG
   2019-04-05: Added switch -NoIP2Location, parameter -OutputPath and "isVpn" column
               Minor improvements
   2019-04-03: Added progress bars and a warning message
   2019-01-31: Fixed compatibility issues with Win10 1809 ETL logs which 
               may contain more than one "ExternalIpAddress" per file
   2018-12-05: First release
#>

[CmdletBinding()]
Param (
[Parameter(Mandatory=$false,Position=0)][string]$LogPath,
[switch]$NoIP2Location,
[Parameter(Mandatory=$false)][string]$OutputPath
)

$script_version = "2019-04-05"

Write-Host "`nGet-DoSvcExternalIP (v.$($script_version))`n" -ForegroundColor Cyan

function Create-Filenames {
	$OutputPath + "\" + $date + $f_description + ".csv"  #$f_ip_csv , $f_ip2loc_csv
    $OutputPath + "\" + $date + $f_description + ".json" #$f_ip_json, $f_ip2loc_json
}

if($LogPath)
	{
	$date = Get-Date -Format "yyyyMMdd_HHmmss"

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

	#Get-DeliveryOptimizationLog cmdlet retrieves decoded logs for Delivery Optimization
	#Available since Windows 10 Insider Preview Build 17074
	#https://blogs.windows.com/windowsexperience/2018/01/11/announcing-windows-10-insider-preview-build-17074-pc/
	$ETLs = Get-ChildItem $LogPath -File -Filter "*.etl" -Recurse | Sort-Object Name
	if($ETLs)
		{
        $f_description        = "_dosvc_ExtIpAddress"
        $f_ip_csv, $f_ip_json = Create-Filenames

        Write-Host "ETL files found   : $($ETLs.Count)" -ForegroundColor Green
        $c1 = 0 #counter
		foreach($ETL in $ETLs)
			{
            $c1++
            Write-Progress -Activity "Processing Event Trace Log (.etl) files:" -Status "Processing $($c1) of $($ETLs.Count)" -CurrentOperation $ETL
			#Decode logs + add a column named LogName which contains the name and path of the log file
			$results = Get-DeliveryOptimizationLog -Path $ETL.FullName | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name LogName -Value $ETL.Basename -PassThru}
			$results = $results | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name LogPath -Value $ETL.DirectoryName -PassThru}
			$results = $results | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name LogFullPath -Value $ETL.FullName -PassThru}

            if($results)
				{
			    #Search for string "ExternalIP"
				$search_ip    = $results | Where-Object {$_.Message -like "*ExternalIP*"}

                #Search for strings: "isvpn", "Detected connected VPN adapter" and "Network connectivity: vpn_connected?"
                $search_isVpn = $results | Select-Object TimeCreated,ProcessId,ThreadId,Message | Where {($_.Message -Like "*isVpn*") -or ($_.Message -Like "*Detected connected VPN adapter*") -or ($_.Message -Like "*Network connectivity: vpn_connected?*")}

                #Prepare isVpn data
                if($search_isVpn)
                    {
                    $search_isVpn = $search_isVpn | Select-Object @{name="TimeCreated";expression={$_.TimeCreated.ToString("yyyy-MM-dd HH:mm")}},ProcessId,ThreadId,Message
                    $search_isVpn = $search_isVpn | Select-Object TimeCreated,ProcessId,ThreadId,@{name="isVpn";expression={$_.Message -replace "Network connectivity: vpn_connected\?","isVpn:"}}
                    $search_isVpn = $search_isVpn | Select-Object TimeCreated,ProcessId,ThreadId,@{name="isVpn";expression={$_.isVpn -replace ".*Detected connected VPN adapter.*","isVpn: 1"}}
                    $search_isVpn = $search_isVpn | Select-Object TimeCreated,ProcessId,ThreadId,@{name="isVpn";expression={$_.isVpn -replace ".*isVpn","isVpn" -replace " =",":"}}
                    $search_isVpn = $search_isVpn | Select-Object TimeCreated,ProcessId,ThreadId,@{name="isVpn";expression={$_.isVpn -split "," -like "isVpn*"}} | Sort-Object TimeCreated -Unique
                    }

				if($search_ip)
					{
                    foreach($ip in $search_ip) #ETL files may contain more than one "ExternalIpAddress" value 
                        {
					    $messageJSON = "[" + ($ip.Message -replace ".*{","{") + "]"
					    $messageCSV = ($messageJSON | ConvertFrom-Json) | Select-Object ExternalIpAddress,CountryCode,KeyValue_EndpointFullUri,Version,CompactVersion,isVpn | ConvertTo-Csv -NoTypeInformation
					    #Add new member "ExternalIpAddress"
					    $ip = $ip | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name ExternalIpAddress -Value ($messageCSV | ConvertFrom-Csv).ExternalIpAddress -PassThru}
					    #Add new member "CountryCode"
					    $ip = $ip | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name CountryCode -Value ($messageCSV | ConvertFrom-Csv).CountryCode -PassThru}
					    #Add new member "KeyValue_EndpointFullUri"
					    $ip = $ip | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name KeyValue_EndpointFullUri -Value ($messageCSV | ConvertFrom-Csv).KeyValue_EndpointFullUri -PassThru}
					    #Add new member "Version"
					    $ip = $ip | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name Version -Value ($messageCSV | ConvertFrom-Csv).Version -PassThru}
					    #Add new member "CompactVersion"
					    $ip = $ip | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name CompactVersion -Value ($messageCSV | ConvertFrom-Csv).CompactVersion -PassThru}
					    #Change the order of the objects
					    $ip = $ip | Select-Object LogName,LogPath,LogFullPath,@{name="TimeCreated";expression={$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")}},ExternalIpAddress,CountryCode,ProcessId,ThreadId,Level,LevelName,KeyValue_EndpointFullUri,Version,CompactVersion,Function,LineNumber,isVpn
                        if($search_isVpn)
                            {
                            foreach($isVpn in $search_isVpn)
                                {
                                if($isVpn.TimeCreated.Substring(0,15) -eq $ip.TimeCreated.Substring(0,15) -and $isVpn.ProcessId -eq $ip.ProcessId)
                                    {
                                    $ip.isVpn = $isVpn.isVpn
                                    }
                                }
                            }
                        $ip = $ip | Select-Object LogName,LogPath,LogFullPath,TimeCreated,ExternalIpAddress,isVpn,CountryCode,ProcessId,ThreadId,Level,LevelName,KeyValue_EndpointFullUri,Version,CompactVersion,Function,LineNumber
					    if(Test-Path $f_ip_csv)
						    {
						    #Skip the first row since the header is already present in the CSV file
						    $ip = $ip | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
						    Add-Content $f_ip_csv -Value $ip
						    }
					    else
						    {
						    $ip | Export-Csv -NoTypeInformation $f_ip_csv
						    }
                        }
					}
				}
			}
		
            if(Test-Path $f_ip_csv)
			    {
			    #JSON OUTPUT
			    $csv = Import-Csv $f_ip_csv
			    $csv | ConvertTo-Json | Out-File $f_ip_json -Encoding utf8

			    $ip_uniq = $csv | Select-Object ExternalIpAddress -unique #get unique IP addresses
			    $ip_uniq = ($ip_uniq | Select-Object -ExpandProperty ExternalIpAddress) | Sort-Object { [version]$_ } #sort by IP address

		        Write-Host "Unique IPs found  : $($ip_uniq.count)" -ForegroundColor Green

                if($PSBoundParameters.ContainsKey('NoIP2Location'))
                    {
                    #SUMMARY: UNIQUE IP ADDRESSES
                    Write-Host "`nUnique IPs and number of occurrences:"
			        $csv | Select-Object ExternalIpAddress | Group-Object ExternalIpAddress -NoElement
			        Write-Host "`nDone! For more details, see the output files:`n==> $f_ip_csv`n==> $f_ip_json`n"
                    }
                else
                    {
			        #IP2LOCATION
                    $f_description = "_dosvc_ip2location"
                    $f_ip2loc_csv, $f_ip2loc_json = Create-Filenames

			        Add-Content $f_ip2loc_json -Value "["
			        $c2 = 0
			        foreach($ip in $ip_uniq)
				        {
				        $c2++
                        Write-Progress -Activity "Performing IP location lookup using ip-api API:" -Status "Processing $($c2) of $($ip_uniq.Count)" -CurrentOperation $ip
				        $url = "http://ip-api.com/json/" + $ip #http://ip-api.com/docs/api:json
				        $LoginResponse = Invoke-WebRequest $url
				        if ($c2 -lt $ip_uniq.Count)
					        {
					        $line = $LoginResponse.Content + ","
					        Add-Content $f_ip2loc_json -Value $line
					        }
				        else {
					         Add-Content $f_ip2loc_json -Value $LoginResponse.Content
					         }
				        Start-Sleep -Seconds 3 #Waiting time between API calls
				        }
			        Add-Content $f_ip2loc_json -Value "]"
			        (Get-Content $f_ip2loc_json | ConvertFrom-Json) | Export-Csv $f_ip2loc_csv -NoTypeInformation

			        #SUMMARY: UNIQUE IP ADDRESSES
			        Write-Host "`nWarning: IP geolocation data could be inaccurate and should be treated with caution" -ForegroundColor Red -BackgroundColor White
                    Write-Host "Double-check the results using other services like 'iplocation.net'" -ForegroundColor Red -BackgroundColor White
			        $ip2loc = (Get-Content $f_ip2loc_json | ConvertFrom-Json)
			        $ip2loc | Select-Object  @{Name="ExternalIp";Expression={$_.query}},isp,city,countrycode | Format-Table -AutoSize
			        Write-Host "Done! For more details, see the output files:`n==> $f_ip_csv`n==> $f_ip_json`n==> $f_ip2loc_csv`n==> $f_ip2loc_json`n"
                    }
			    }
            else
			    {
			    Write-Host "IP addresses found: 0`n" -ForegroundColor Yellow
			    }
		}
	else
		{
		Write-Host "ETL files found: 0`n" -ForegroundColor Yellow
		}
	}
else
	{
    Write-Host "Extracts external/public IP addresses from DoSvc ETL logs and performs an IP address lookup using the free 'ip-api' API"
	Write-Host "`nExamples:"
    Write-Host ".\Get-DoSvcExternalIP.ps1 C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs"
    Write-Host ".\Get-DoSvcExternalIP.ps1 C:\CustomLogPath -NoIP2Location -OutputPath C:\CustomOutputPath"
    Write-Host ".\Get-DoSvcExternalIP.ps1 dosvc.20181212_133942_927.etl`n"
	}