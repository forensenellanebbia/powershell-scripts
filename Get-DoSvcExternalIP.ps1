<# 
  .SYNOPSIS
   Extracts external/public IP addresses from DoSvc ETL logs and performs an IP Address Lookup
  .DESCRIPTION
   Extracts external/public IP addresses from DoSvc ETL logs and performs an IP Address Lookup.
   Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
   Win10 1507  | C:\Windows\Logs\dosvc
   Win10 1709+ | C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

   Test environment: (OS) Windows 10 Pro ENG (version 1803/1809) + Powershell 5.1
   Script tested against logs collected from:
     - Windows 10 Home x86 ENG (version 1507)
     - Windows 10 Pro x64 ENG  (version 1709/1803/1809)
  .EXAMPLE
   Get-DoSvcExternalIP.ps1 C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

   This command recursively parses a path.
  .EXAMPLE
   Get-DoSvcExternalIP.ps1 dosvc.20181212_133942_927.etl

   This command parses a file.
  .NOTES
   Author       : Gabriele Zambelli
   Twitter      : @gazambelli
   Repository   : https://github.com/forensenellanebbia
   Blog post    : https://forensenellanebbia.blogspot.it/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html

   CHANGELOG
   2019/01/31: Fixed compatibility issues with Win10 1809 ETL logs which 
               may contain more than one "ExternalIpAddress" per file
   2018/12/05: First release
#>

[CmdletBinding()]
Param([Parameter(Mandatory=$false,Position=0)][string]$path)

$script_version = "2019/01/31"

if($path)
	{
	#FILENAMES
	$date          = Get-Date -Format "yyyyMMdd_HHmmss"
	$f_ip_csv      = $date + "_dosvc_ExtIpAddress.csv"
	$f_ip_json     = $date + "_dosvc_ExtIpAddress.json"
	$f_ip2loc_json = $date + "_dosvc_ip2location.json"
	$f_ip2loc_csv  = $date + "_dosvc_ip2location.csv"
	
	#Get-DeliveryOptimizationLog cmdlet retrieves decoded logs for Delivery Optimization
	#Available since Windows 10 Insider Preview Build 17074
	#https://blogs.windows.com/windowsexperience/2018/01/11/announcing-windows-10-insider-preview-build-17074-pc/
	$items = Get-ChildItem $path -File -Filter "*.etl" -Recurse | Sort-Object Name
	if($items)
		{
        Write-Host "`nAnalyzing $($items.Count) ETL file(s)...`n"
		foreach($item in $items.FullName)
			{
			#Decode logs + add a column named LogName which contains the name and path of the log file
			$results = Get-DeliveryOptimizationLog -Path $item | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name LogName -Value $item -PassThru}
			#SEARCH FOR THE STRING "ExternalIP"
			if($results)
				{
				$search_ip = $results | Where-Object {$_.Message -like "*ExternalIP*"}
				if($search_ip)
					{
                    foreach($ip in $search_ip) #ETL files may contain more than one "ExternalIpAddress" value 
                        {
					    $messageJSON = "[" + ($ip.Message -replace ".*{","{") + "]"
					    $messageCSV = ($messageJSON | ConvertFrom-Json) | Select-Object ExternalIpAddress,CountryCode,KeyValue_EndpointFullUri,Version,CompactVersion | ConvertTo-Csv -NoTypeInformation
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
					    $ip = $ip | Select-Object LogName,TimeCreated,ExternalIpAddress,CountryCode,ProcessId,ThreadId,Level,LevelName,KeyValue_EndpointFullUri,Version,CompactVersion,Function,LineNumber
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

			#IP2LOCATION
			$ip_uniq = $csv | Select-Object ExternalIpAddress -unique #get unique IP addresses
			$ip_uniq = ($ip_uniq | Select-Object -ExpandProperty ExternalIpAddress) | Sort-Object { [version]$_ } #sort by IP address
			Add-Content $f_ip2loc_json -Value "["
			$i = 0
			foreach($ip in $ip_uniq)
				{
				Start-Sleep -Seconds 3 #Waiting time between API calls
				$url = "http://ip-api.com/json/" + $ip #http://ip-api.com/docs/api:json
				$LoginResponse = Invoke-WebRequest $url
				$i++
				if ($i -lt $ip_uniq.Count)
					{
					$line = $LoginResponse.Content + ","
					Add-Content $f_ip2loc_json -Value $line
					}
				else {
					 Add-Content $f_ip2loc_json -Value $LoginResponse.Content
					 }
				}
			Add-Content $f_ip2loc_json -Value "]"
			(Get-Content $f_ip2loc_json | ConvertFrom-Json) | Export-Csv $f_ip2loc_csv -NoTypeInformation

			#SUMMARY: UNIQUE IP ADDRESSES
			Write-Output ("`nUnique IP(s) found: " + $ip_uniq.count)
			$ip2loc = (Get-Content $f_ip2loc_json | ConvertFrom-Json)
			$ip2loc | Select-Object  @{Name="ExternalIp";Expression={$_.query}},isp,city,countrycode | Format-Table -AutoSize
			Write-Host "Done! For more details, see the output files:`n==> $f_ip_csv`n==> $f_ip_json`n==> $f_ip2loc_csv`n==> $f_ip2loc_json`n"
			}
		else
			{
			Write-Host "No IP address found`n"
			}
		}
	else
		{
		Write-Host "`nNo ETL files found`n"
		}
	}
else
	{
	Write-Host "`nGet-DoSvcExternalIP (v.$($script_version)):"
    Write-Host "Extracts external/public IP addresses from DoSvc ETL logs and performs an IP address lookup"
	Write-Host "`nExamples:"
    Write-Host "Get-DoSvcExternalIP.ps1 C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs"
    Write-Host "Get-DoSvcExternalIP.ps1 dosvc.20181212_133942_927.etl`n"
	}