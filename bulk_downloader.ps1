<#
Author : Gabriele Zambelli
Blog   : https://forensenellanebbia.blogspot.it
Twitter: @gazambelli

I wrote this script to download files in bulk from conference websites

How to use:
  .\bulk_downloader.ps1 <uri>

Change History:
    2020-06-06 First release

Tested against:
  - https://www.first.org/resources/papers/2020
  - https://dfrws.org/eu-2020-program/
  - https://www.sans.org/cyber-security-summit/archives/dfir
  - https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/
  - https://conference.hitb.org/hitbsecconf2019ams/materials/
  - conference.hitb.org/hitbsecconf2013ams/materials/
  - https://recon.cx/2018/brussels/slides/
  - https://www.bluehatil.com/abstracts
  - https://2019.pass-the-salt.org/schedule/

#>

# File extensions to download
$extensions   = @("pdf","pptx")

# Download slides published in the last XX days - this setting works with sans.org only
$last_nn_days = 120


$uri = $args[0]

if ($uri) {
    Write-Host "These are the file extensions that have been selected:`n$extensions"
    $html = Invoke-WebRequest -Uri $uri
    foreach ($extension in $extensions) {
        $i=0
        #U: https://www.sans.org/cyber-security-summit/archives/dfir
        #H: https://www.sans.org/cyber-security-summit/archives/file/summit_archive_<10-digit epoch ts>.pdf
        if($uri -like "*sans.org*"){
            $last_nn_days2epoch_ts = [int64](([datetime]::UtcNow).AddDays(-$last_nn_days)-(get-date "1/1/1970")).TotalSeconds
            $files_to_download = $html.Links.href | Where-Object { $_ -like ("*." + $extension) -and $_ -notlike "*trademarkuse.pdf" -and $_.substring(($_.length)-14),(($_.length)-4) -ge $last_nn_days2epoch_ts}
        }
        else {
            $files_to_download = $html.Links.href | Where-Object { $_ -like ("*." + $extension)}
        }
        Write-Host "`n** Downloading now $($files_to_download.Count) .$($extension.ToUpper()) file(s)"
        $files_to_download | ForEach-Object { 
            Start-Sleep -Seconds 1
            #URI cleanup
            $_ = $_ -replace "&amp;","&" -replace "&#32;"," "
            $filename = $_ -replace "^.*/",""
            #Filename cleanup
            $filename = [System.Web.HttpUtility]::UrlDecode($filename) -replace ":","" -replace "&#32;"," "
            $i++
            Write-Host "    $i`t$filename"

            #U: https://www.sans.org/cyber-security-summit/archives/dfir
            #H: https://www.sans.org/cyber-security-summit/archives/file/summit_archive_<10-digit epoch ts>.pdf
            if($_.StartsWith("http")) {
                Invoke-WebRequest -Uri $_ -OutFile $filename
            } 

            #U: https://www.sstic.org/2020/presentation/<talk title>/
            #H: //www.sstic.org/media/SSTIC2020/SSTIC-actes/<talk title>/filename.pdf
            elseif($_.StartsWith("//")) {
                Invoke-WebRequest -Uri ("https:" + $_) -OutFile $filename
            } 

            #U: https://www.first.org/resources/papers/2020
            #H: /resources/papers/path/filename.pdf
            elseif($_.StartsWith("/") -and $_.substring(1,1) -ne "/") {
                Invoke-WebRequest -Uri (($uri.Split("/")[0..2] -join "/") + $_) -OutFile $filename
            } 

            #U: http://domain.com/path/page.htm
            #H: Path/filename.pdf
            elseif(-not $_.StartsWith("/") -and $_ -like "*/*") {
                Invoke-WebRequest -Uri (($uri | Select-String -pattern ".*/").Matches.Value + $_) -OutFile $filename
            } 
            
            #U: https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/
            #H: filename.pdf
            else { 
                Invoke-WebRequest -Uri ($uri + $_) -OutFile $filename
            }
        }
    }
    Write-Host "`nDone!`n"
}
else { 
    Write-Host "Please provide a URI"
}