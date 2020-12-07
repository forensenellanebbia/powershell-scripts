# powershell-scripts

**Get-DoSvc4n6.ps1** extracts external/public IP addresses and more from DoSvc ETL logs.
Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
- [1507]  C:\Windows\Logs\dosvc
- [1709+] C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

Blog post: https://forensenellanebbia.blogspot.com/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html <br>
DFIR Review: https://dfir.pubpub.org/pub/httnwst7

~~**Get-VlcLastPlayedPosition.ps1** extracts the last played position of the files opened with VLC media player. The script parses the *RecentsMRL* section of the *vlc-qt-interface.ini* file which is located under: *C:\Users\\<username\>\AppData\Roaming\vlc*~~ I replaced this script with another version available [here](https://github.com/forensenellanebbia/python27-scripts).

**bulk_downloader.ps1** downloads files in bulk from conference websites

**ConvertTo-LogonTracer.ps1** converts an XML file created with EvtxECmd to the XML format needed by LogonTracer. The script can also search for keywords and splits a large XML into smaller chunks. Before running the script, edit the "settings section" inside the script to set the variables related to: source file, destination path, keywords to search and desired max number of events per output file.

Blog post: https://forensenellanebbia.blogspot.com/2020/12/lets-combine-evtxecmd-with-logontracer.html <br>
