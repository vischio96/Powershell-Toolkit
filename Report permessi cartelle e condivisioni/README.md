# Report permessi cartelle e condivisioni

Script PowerShell in sola lettura che genera un report HTML dei permessi NTFS e di condivisione SMB di cartelle locali o share di rete.

```powershell
.\Get-SharePermissionReport.ps1 -Path '\\FS01\Dati' -Depth 4 -OpenReport
```

Requisiti: Windows PowerShell 5.1 o PowerShell 7 su Windows.
Parametri ed esempi completi: `Get-Help .\Get-SharePermissionReport.ps1 -Full`.

Revisioni: [CHANGELOG.md](CHANGELOG.md)
