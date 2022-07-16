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
   This script converts an XML file created with EvtxECmd to an XML that can be imported into LogonTracer.
  .DESCRIPTION
   This script converts an XML file created with EvtxECmd to an XML that can be imported into LogonTracer. It can also split the input file into smaller XML files and can search for keywords. Based on tests: ~320MB XML processed in ~16min.

   Test environment:
   (OS) Windows 10 Pro ENG 21H2
        # EvtxECmd (v1.0.0.0)
        # Powershell 7.2.5 / Powershell 5.1
   (OS) REMnux v7 Focal (Ubuntu 20.04.1 LTS)
        # LogonTracer (Dockerfile: Dec 19, 2021) | https://github.com/JPCERTCC/LogonTracer/tree/master/docker
  .PARAMETER InputXML
   Path to the XML source file to parse. No other file formats are currently supported by the script.
  .PARAMETER OutputPath
   Output path
  .PARAMETER SplitAt
   Maximum number of events per XML ouput file
  .PARAMETER Keywords
   Comma separated keywords to search. The search is case insensitive and the keywords are searched as substrings.
  .EXAMPLE
   First parse the EVTX files with EvtxECmd and save the ouput in XML format. Examples:
   EvtxECmd.exe -d <path_to_EVTX> --xml <output_path> --xmlf evtxecmd.xml --inc 4624,4625,4768,4769,4776,4672
   EvtxECmd.exe -d <path_to_EVTX> --xml <output_path> --xmlf evtxecmd.xml --inc 4624,4625,4768,4769,4776,4672 --sd "2020-12-06 00:00:00" --ed "2020-12-07 00:00:00"
   
   Then run the script to make the XML file compatible with LogonTracer. Examples:

   ConvertTo-LogonTracer.ps1 -InputXML .\evtxecmd.xml
   ConvertTo-LogonTracer.ps1 -InputXML .\evtxecmd.xml -SplitAt 10000 -Keywords keyword1,keyword2,keyword3

  .NOTES
   Author       : Gabriele Zambelli
   Twitter      : @gazambelli

   CHANGELOG
   2022-07-16: It's no longer needed to manually edit the script to set it up
   2020-12-07: First release
  .LINK
   GitHub     : https://github.com/forensenellanebbia/powershell-scripts
   Blog post  : https://forensenellanebbia.blogspot.com/2020/12/lets-combine-evtxecmd-with-logontracer.html
#>

[CmdletBinding()]
Param (
	[Parameter(Position=0,Mandatory = $True)][string]$InputXML,
	[Parameter(Position=1,Mandatory = $False)][string]$OutputPath = (Get-ChildItem $InputXML).DirectoryName,
	[Parameter(Position=2,Mandatory = $False)][int]$SplitAt = 5000,
	[Parameter(Position=2,Mandatory = $False)][string[]]$Keywords = ""
)

$InputXML = (Get-ChildItem $InputXML).FullName

function New-File ($DstPartNumber){
    $DstFile = $OutputPath + "\" + $DstFileTemplateName + "_" + $Suffix + "_" + $DstPartNumber + ".xml"
    return $DstFile
   }

$StartTimeNoFormat = Get-Date
$StartTime = Get-Date -date $StartTimeNoFormat -format "yyyy-MM-dd HH:mm:ss"
$Suffix    = Get-Date -date $StartTimeNoFormat -format "yyyyMMdd_HHmmss"
$DstFileTemplateName = "EvtxECmd_LogonTracer"

Write-Host "`n*** ConvertTo-LogonTracer (v2022-07-16) *** "
Write-Host "Start Time         : $StartTime"
Write-Host "`nINPUT"
Write-Host "Source File        : $InputXML"

$SrcNumberLines = [Linq.Enumerable]::Count([System.IO.File]::ReadLines($InputXML))
$SrcNumberLine  = 0
$DstNumberLines = 1
$DstPartNumber  = 1
$XmlHeader      = '<?xml version="1.0" encoding="utf-8" standalone="yes"?><Events>'
$XmlFooter      = "</Events>"

Write-Host "Lines to parse     : $SrcNumberLines"
Write-Host "`nOUTPUT"
Write-Host "Keywords to search : $(($Keywords -notlike '').Count)" 
Write-Host "Max events per file: $SplitAt"
Write-Host "Output path        : $OutputPath"
Write-Host "Output file(s)     : $($DstFileTemplateName+'_'+$Suffix+'_###.xml')"

$KeywordMatches = 0

foreach($SrcLine in [System.IO.File]::ReadLines($InputXML)){
    $SrcNumberLine++
    $StepPercentage = [int]($SrcNumberLines/100)
    if($SrcNumberLine -eq 1){
        Write-Host "`nProgress: " -NoNewline
    }
    if(($SrcNumberLine % $StepPercentage) -eq 0){
        Write-Host "$(($SrcNumberLine/$SrcNumberLines).tostring("P")).." -NoNewline
    }
    $DstFile = New-File($DstPartNumber)
    if($SrcLine -eq "<Event>"){
        $MergedElements = $SrcLine
    }
    else{
        $MergedElements +=  $SrcLine -join ("")
        if($SrcLine -eq "</Event>"){
            $MergedElements = $MergedElements -replace "<Event>","<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" -replace ">[ ]*<","><"
            if(($Keywords -notlike '').Count -gt 0){
                $KeywordFound = 0
                $Keywords | ForEach-Object{
                    if($MergedElements -match $_){
                        $KeywordFound++
                        $KeywordMatches++
                    }
                }
            }
            if(($Keywords -notlike '').Count -eq 0 -or $KeywordFound -gt 0){
                if($DstNumberLines -eq 1){
                    Add-Content $DstFile -Value $XmlHeader -NoNewline
                    Add-Content $DstFile -Value $MergedElements -NoNewline
                    $DstNumberLines++
                }
                elseif($DstNumberLines -ne 1 -and $DstNumberLines -lt $SplitAt){
                    try {
                        Add-Content $DstFile -Value $MergedElements -NoNewline
                    }
                    catch {
                        Start-Sleep -Seconds 2
                        Add-Content $DstFile -Value $MergedElements -NoNewline
                    }
                    if($SrcNumberLine -eq $SrcNumberLines){
                        Add-Content $DstFile -Value $XmlFooter -NoNewline
                    }
                    $DstNumberLines++
                }
                elseif($DstNumberLines -eq $SplitAt){
                    Add-Content $DstFile -Value $XmlFooter -NoNewline
                    $DstPartNumber++
                    $DstFile = New-File($DstPartNumber)
                    $DstNumberLines = 2
                    Add-Content $DstFile -Value $XmlHeader -NoNewline
                    Add-Content $DstFile -Value $MergedElements -NoNewline
                }
            }
            elseif(($Keywords -notlike '').Count -gt 0 -and $KeywordFound -eq 0){
                if($SrcNumberLine -eq $SrcNumberLines){
                    Add-Content $DstFile -Value $XmlFooter -NoNewline
                }
            }
        }
    }    
}

Write-Host "Done!"
$EndTime = Get-Date -format "yyyy-MM-dd HH:mm:ss"

if(($Keywords -notlike '').Count -gt 0){
	Write-Host "`nNumber of matches  : $KeywordMatches"
}

Write-Host "`nEnd Time: $EndTime"
