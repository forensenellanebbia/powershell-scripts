# powershell-scripts

## [DFIR]

**Get-DoSvc4n6.ps1** extracts external/public IP addresses and more from DoSvc ETL logs.
Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
- [1507]  C:\Windows\Logs\dosvc
- [1709+] C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

Blog post: https://forensenellanebbia.blogspot.com/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html <br>
DFIR Review: https://dfir.pubpub.org/pub/httnwst7

**ConvertTo-LogonTracer.ps1** converts a filtered XML file created with [EvtxECmd](https://ericzimmerman.github.io) to an XML that can be imported into [LogonTracer](https://github.com/JPCERTCC/LogonTracer). That allows to load into LogonTracer just the events that the tool can interpret, speeding up the whole process. The script can also search for keywords and splits a large XML into smaller chunks. 

Blog post: https://forensenellanebbia.blogspot.com/2020/12/lets-combine-evtxecmd-with-logontracer.html <br>

## [MISC]

**bulk_downloader.ps1** downloads files in bulk from conference websites
