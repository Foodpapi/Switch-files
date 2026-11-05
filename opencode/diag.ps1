$ErrorActionPreference = 'SilentlyContinue'

Write-Output '=== Recent storage-related errors/warnings ==='
Get-WinEvent -LogName System -MaxEvents 600 |
    Where-Object {
        $_.ProviderName -match 'disk|storahci|USBSTOR|usbhub|sd|Ntfs|volmgr|partmgr' -and
        ($_.Level -eq 1 -or $_.Level -eq 2 -or $_.Level -eq 3)
    } |
    Select-Object -First 20 TimeCreated, ProviderName, Id, LevelDisplayName,
        @{n = 'Msg'; e = { ($_.Message -split [char]10)[0] } } |
    Format-Table -AutoSize -Wrap

Write-Output ''
Write-Output '=== Disks now ==='
Get-Disk | Select-Object Number, FriendlyName, BusType, OperationalStatus, @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 1) } } |
    Format-Table -AutoSize

Write-Output ''
Write-Output '=== Attempting host storage rescan ==='
Update-HostStorageCache
Start-Sleep -Seconds 2
Get-Disk | Select-Object Number, FriendlyName, BusType, OperationalStatus, @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 1) } } |
    Format-Table -AutoSize

Write-Output ''
Write-Output '=== Volumes now ==='
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, OperationalStatus, @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 1) } }, @{n = 'FreeGB'; e = { [math]::Round($_.SizeRemaining / 1GB, 1) } } |
    Format-Table -AutoSize
