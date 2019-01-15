<# 
  .SYNOPSIS
   Extracts the last played position of the files opened with VLC media player
  .DESCRIPTION
   VLC media player allows to restart the playback where left off.
   Last played positions (one per media file) are stored in a file named "vlc-qt-interface.ini" under the path: C:\Users\<username>\AppData\Roaming\vlc.
   This script parses the "RecentsMRL" section of the .INI file. The values are expressed in milliseconds (1000ms = 1s).
   Based on my tests with VLC v3.0.5, a zero value may either mean that the file has been fully played or that less than 5 percent of the file contents has been played.
   Filenames are listed by default in MRU order.
  .EXAMPLE
   Get-VlcLastPlayedPosition.ps1 vlc-qt-interface.ini
  .NOTES
   Author       : Gabriele Zambelli
   Twitter      : @gazambelli
   Repository   : https://github.com/forensenellanebbia
   Blog         : https://forensenellanebbia.blogspot.it
   Version      : 1.0
   Creation date: 2019-01-15
#>

[CmdletBinding()]
Param([Parameter(Mandatory=$false,Position=0)][string]$path)

if ($path) {
    $TestFile = Test-Path $path
    if ($TestFile -eq "True") {
        $vlc_f = (Get-Content $path).Split("`n") | Select-String -Pattern "RecentsMRL" -Context 0,2
        $vlc_f = $vlc_f -split "`n"

        #VLC list
        $vlc_l = $vlc_f | Select-String -Pattern "list="
        $vlc_l = $vlc_l -replace("^ ","") -replace(" $","")
        $vlc_l = $vlc_l -replace "list=" -replace "file:///"
        if ($vlc_l.Length -gt 1) {
            $vlc_l = $vlc_l.split(",", [StringSplitOptions]::RemoveEmptyEntries)

            #VLC times
            $vlc_t = $vlc_f | Select-String -Pattern "times="
            $vlc_t = $vlc_t -replace("^ ","") -replace(" $","")
            $vlc_t = $vlc_t -replace "times="
            $vlc_t = $vlc_t.split(",", [StringSplitOptions]::RemoveEmptyEntries)

            $i     = 0
            $nItem = 1
            $oFile = "VLC_LastPlayedPosition.csv"
            Write-Host "`nVLC media player"
            Write-Host "`n$("*" * 60)`n#    | LastPlayed |  Full Path`n     | Position   |  (The output is by default in MRU order)`n$("*" * 60)"
            "#`tLast Played Position (hh:mm:ss)`tLast Played Position (milliseconds)`tFull Path" | Out-File $oFile
            foreach ($lpp in $vlc_t) {
                    if ([int]$lpp -gt 0) {
                        $lpp = [timespan]::fromseconds($lpp / 1000) #LastPlayedPosition is in milliseconds
                        $lpp = ("{0:HH\:mm\:ss}" -f [string]$lpp).Substring(0,8)
                    }
                    else {
                        $lpp = "N/A" + " " * 5
                    }
                    Add-Type -AssemblyName System.Web
                    Write-Host $nItem $(" " * (3 - ([string]$nItem).Length)) "|" $lpp "  |" $([System.Web.HttpUtility]::UrlDecode($vlc_l[$i]))
                    "$nItem`t$($lpp.TrimEnd())`t$($vlc_t[$i])`t$($([System.Web.HttpUtility]::UrlDecode($vlc_l[$i])).TrimStart())" | Out-File $oFile -Append
                $i++
                $nItem++
            }
            Write-Host "`n`nTab-delimited output file: $oFile`n`n"
        }
        else {
            Write-Host "`nThe 'RecentsMRL' section is empty`n"
        }
    }
    else {
        Write-Host "`n Error: file not found`n"
    }
}
else {
    Write-Host "`nScript to extract the last played position of the files opened with VLC media player"
    Write-Host "`nExample: .\Get-VlcLastPlayedPosition.ps1 C:\Users\<username>\AppData\Roaming\vlc\vlc-qt-interface.ini`n"
}


