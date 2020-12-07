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

Author      : Gabriele Zambelli @gazambelli
Blog post   : https://forensenellanebbia.blogspot.com/2020/12/lets-combine-evtxecmd-with-logontracer.html

This script:
    - converts an XML created with EvtxECmd to an XML that can be imported into LogonTracer
    - splits a large XML into smaller XML files
    - can search for keywords

Last updated: 2020-12-07
Tested with : EvtxECmd (v0.6.0.3)  | https://ericzimmerman.github.io
              LogonTracer (v1.5.0) | https://github.com/JPCERTCC/LogonTracer/releases/tag/v1.5.0
How to use  : 
    1) Parse the EVTX files with EvtxECmd and save the ouput in XML format.
            Examples:
                EvtxECmd.exe -d <path_to_your_evtx> --xml <output_path> --xmlf evtxecmd.xml --inc 4624,4625,4768,4769,4776,4672
                EvtxECmd.exe -d <path_to_your_evtx> --xml <output_path> --xmlf evtxecmd.xml --inc 4624,4625,4768,4769,4776,4672 --sd "2020-12-06 00:00:00" --ed "2020-12-07 00:00:00"
    2) Customize the settings of this script based on your needs by editing the lines in the Script Settings section below:
        $SrcFile  = "<Absolute path to your XML source file>"
        $DstPath  = "<Absolute path to your output folder>"
        $SplitAt  = desired max number of events per XML ouput file
        $Keywords = Default setting is an empty array which means no keywords to search for.
            Examples:
                @("") = default setting, no keywords
                @("keyword1","keyword2","keyword3") = in the way shown, list one or more keywords to search for.
                The search is case insensitive and the keywords are searched as substrings.
    3) Run the PowerShell script: .\ConvertTo-LogonTracer.ps1
       (Based on tests: ~320MB XML processed in ~16min)
    4) Import each XML created by the script into LogonTracer
#>

# SCRIPT SETTINGS - BEGIN
# Customize the script settings here
$SrcFile  = "C:\TEMP\evtxecmd.xml"
$DstPath  = "C:\TEMP"
$SplitAt  = 5000
$Keywords = @("")
# SCRIPT SETTINGS - END

function New-File ($DstPartNumber){
    $DstFile = $DstPath + "\" + $DstFileTemplateName + "_" + $Suffix + "_" + $DstPartNumber + ".xml"
    return $DstFile
   }

$StartTimeNoFormat = Get-Date
$StartTime = Get-Date -date $StartTimeNoFormat -format "yyyy-MM-dd HH:mm:ss"
$Suffix    = Get-Date -date $StartTimeNoFormat -format "yyyyMMdd_HHmmss"
$DstFileTemplateName = "EvtxECmd_LogonTracer"

Write-Host "Start Time         : $StartTime"
Write-Host "`nINPUT"
Write-Host "Source File        : $SrcFile"

$SrcNumberLines = [Linq.Enumerable]::Count([System.IO.File]::ReadLines($SrcFile))
$SrcNumberLine  = 0
$DstNumberLines = 1
$DstPartNumber  = 1
$XmlHeader      = '<?xml version="1.0" encoding="utf-8" standalone="yes"?><Events>'
$XmlFooter      = "</Events>"

Write-Host "Lines to parse     : $SrcNumberLines"
Write-Host "`nOUTPUT"
Write-Host "Keywords to search : $(($Keywords -notlike '').Count)" 
Write-Host "Max events per file: $SplitAt"
Write-Host "Output path        : $DstPath"
Write-Host "Output file(s)     : $($DstFileTemplateName+'_'+$Suffix+'_###.xml')"

foreach($SrcLine in [System.IO.File]::ReadLines($SrcFile)){
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
Write-Host "`nEnd Time: $EndTime"