# powershell-scripts

**Get-DoSvcExternalIP.ps1** extracts external/public IP addresses from DoSvc ETL logs and performs an IP Address Lookup.
Depending on the version of Win10, Delivery Optimization Logs are stored by default in the path:
- [1507]  C:\Windows\Logs\dosvc
- [1709+] C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs

Blog post: https://forensenellanebbia.blogspot.com/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html
