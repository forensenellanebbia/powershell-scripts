# powershell-scripts

**Get-DoSvcExternalIP.ps1** extracts external/public IP addresses from DoSvc ETL logs and performs an IP Address Lookup.
Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
- [1507]  C:\Windows\Logs\dosvc
- [1709+] C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

Blog post: https://forensenellanebbia.blogspot.com/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html <br>
DFIR Review: https://dfir.pubpub.org/pub/httnwst7

~~**Get-VlcLastPlayedPosition.ps1** extracts the last played position of the files opened with VLC media player. The script parses the *RecentsMRL* section of the *vlc-qt-interface.ini* file which is located under: *C:\Users\\<username\>\AppData\Roaming\vlc*~~ I replaced this script with another version available [here](https://github.com/forensenellanebbia/python27-scripts).
