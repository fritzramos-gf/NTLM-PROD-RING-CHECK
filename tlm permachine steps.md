# NTLM Verification Steps — Per-Machine Checklist
**Policy:** GF Server - Disable NTLM Authentication on Server  
**Enforcement:** GF Server - Prod Ring Zero Enforcement (Tanium Enforce)  
**Date:** 2026-06-08

Run each section on or against the named server. All remote commands can be run from a single jump host with admin rights and WinRM access to the servers.

---

## How to Use This Document

For each server, complete the three checks in order:

1. **Registry Check** — confirm the policy settings are written correctly
2. **Event Log Check** — confirm no NTLM blocks or errors are firing
3. **secedit Export** — confirm the effective security policy matches expected values

Record the results in the status table at the bottom of each server section.

---

## SEAFTPv01

### Registry Check
```powershell
Invoke-Command -ComputerName SEAFTPv01 -ScriptBlock {
    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                                -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
        RestrictSendingNTLM  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic
        NtlmMinServerSec     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    }
}
```

### Event Log Check
```powershell
Invoke-Command -ComputerName SEAFTPv01 -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $events = Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
    Write-Host "NTLM Warning/Error events (last 7 days): $($events.Count)"
    $events | Select-Object TimeCreated, Id, Message | Format-List
}
```

### secedit Export
```powershell
Invoke-Command -ComputerName SEAFTPv01 -ScriptBlock {
    $f = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $f /quiet
    Select-String -Path $f -Pattern "LmCompatibilityLevel|NTLM"
    Remove-Item $f -Force
}
```

### Results
| Check | Expected | Actual | Status |
|---|---|---|---|
| LmCompatibilityLevel | 5 | | |
| RestrictSendingNTLMTraffic | 2 | | |
| NtlmMinServerSec | 537395200 | | |
| NTLM Event Errors (7d) | 0 | | |

---

## SEASCOMMGTv03

### Registry Check
```powershell
Invoke-Command -ComputerName SEASCOMMGTv03 -ScriptBlock {
    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                                -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
        RestrictSendingNTLM  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic
        NtlmMinServerSec     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    }
}
```

### Event Log Check
```powershell
Invoke-Command -ComputerName SEASCOMMGTv03 -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $events = Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
    Write-Host "NTLM Warning/Error events (last 7 days): $($events.Count)"
    $events | Select-Object TimeCreated, Id, Message | Format-List
}
```

> **Note:** SEASCOMMGTv03 is a SCOM Management server. It is expected to have outbound connections to other servers for monitoring. If NTLM events appear here, check whether agent-to-management-server communication is the source and consider adding a server exception for SCOM traffic.

### secedit Export
```powershell
Invoke-Command -ComputerName SEASCOMMGTv03 -ScriptBlock {
    $f = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $f /quiet
    Select-String -Path $f -Pattern "LmCompatibilityLevel|NTLM"
    Remove-Item $f -Force
}
```

### Results
| Check | Expected | Actual | Status |
|---|---|---|---|
| LmCompatibilityLevel | 5 | | |
| RestrictSendingNTLMTraffic | 2 | | |
| NtlmMinServerSec | 537395200 | | |
| NTLM Event Errors (7d) | 0 | | |

---

## SEASCOMRPTv01

### Registry Check
```powershell
Invoke-Command -ComputerName SEASCOMRPTv01 -ScriptBlock {
    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                                -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
        RestrictSendingNTLM  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic
        NtlmMinServerSec     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    }
}
```

### Event Log Check
```powershell
Invoke-Command -ComputerName SEASCOMRPTv01 -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $events = Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
    Write-Host "NTLM Warning/Error events (last 7 days): $($events.Count)"
    $events | Select-Object TimeCreated, Id, Message | Format-List
}
```

> **Note:** SEASCOMRPTv01 is the SCOM Reporting server. It may generate NTLM events related to SQL Reporting Services authentication. If events appear, check whether SSRS is configured to use Windows Authentication and whether it is using Kerberos or NTLM.

### secedit Export
```powershell
Invoke-Command -ComputerName SEASCOMRPTv01 -ScriptBlock {
    $f = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $f /quiet
    Select-String -Path $f -Pattern "LmCompatibilityLevel|NTLM"
    Remove-Item $f -Force
}
```

### Results
| Check | Expected | Actual | Status |
|---|---|---|---|
| LmCompatibilityLevel | 5 | | |
| RestrictSendingNTLMTraffic | 2 | | |
| NtlmMinServerSec | 537395200 | | |
| NTLM Event Errors (7d) | 0 | | |

---

## SQLSLv01

### Registry Check
```powershell
Invoke-Command -ComputerName SQLSLv01 -ScriptBlock {
    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                                -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
        RestrictSendingNTLM  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic
        NtlmMinServerSec     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    }
}
```

### Event Log Check
```powershell
Invoke-Command -ComputerName SQLSLv01 -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $events = Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
    Write-Host "NTLM Warning/Error events (last 7 days): $($events.Count)"
    $events | Select-Object TimeCreated, Id, Message | Format-List
}
```

> **Note:** SQLSLv01 is a SQL Server. SQL Server connections use Windows Authentication and require Kerberos SPNs to be properly registered to avoid NTLM fallback. If events appear, run `setspn -L SQLSLv01` to verify SPN registration for the SQL service account.

### secedit Export
```powershell
Invoke-Command -ComputerName SQLSLv01 -ScriptBlock {
    $f = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $f /quiet
    Select-String -Path $f -Pattern "LmCompatibilityLevel|NTLM"
    Remove-Item $f -Force
}
```

### SQL-Specific SPN Check
```powershell
# Verify SQL Server has correct SPNs registered (required for Kerberos auth)
setspn -L SQLSLv01
```

### Results
| Check | Expected | Actual | Status |
|---|---|---|---|
| LmCompatibilityLevel | 5 | | |
| RestrictSendingNTLMTraffic | 2 | | |
| NtlmMinServerSec | 537395200 | | |
| NTLM Event Errors (7d) | 0 | | |
| SQL SPN Registered | Yes | | |

---

## DELLOMEFLSv01

> ⚠️ **Active Issue** — This server has confirmed NTLM block events. See full investigation document: `NTLM_Investigation_DELLOMEFLSv01.md`

### Registry Check
```powershell
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                                -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
        RestrictSendingNTLM  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic
        NtlmMinServerSec     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    }
}
```

### Event Log Check
```powershell
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $events = Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
    Write-Host "NTLM Warning/Error events (last 7 days): $($events.Count)"
    $events | Select-Object TimeCreated, Id, Message | Format-List
}
```

### Identify SMB Connection Target (Outstanding Step)
```powershell
# Resolve the target of the active SMB connection from DELLOMEFLSv01
Resolve-DnsName 10.10.2.61

# Check SMB connections and mapped drives
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    Write-Host "--- SMB Connections ---"
    Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect

    Write-Host "`n--- Mapped Drives ---"
    Get-WmiObject Win32_MappedLogicalDisk | Select-Object Name, ProviderName

    Write-Host "`n--- Net Use ---"
    net use
}
```

### Check NTLM Exception List
```powershell
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
     -Name "ClientAllowedNTLMServers" -ErrorAction SilentlyContinue).ClientAllowedNTLMServers
}
```

### Results
| Check | Expected | Actual | Status |
|---|---|---|---|
| LmCompatibilityLevel | 5 | Enforced | ✅ |
| RestrictSendingNTLMTraffic | 2 | 2 | ✅ |
| NtlmMinServerSec | 537395200 | TBC | |
| NTLM Event Errors (7d) | 0 | 50+ (Event 4002) | 🔴 |
| SMB target 10.10.2.61 identified | Yes | Pending | ⏳ |
| Root cause identified | Yes | RPC/svchost PID 444 | 🔴 |
| Remediation applied | Yes | Pending | ⏳ |

---

## SEAIPSUTLv01

### Registry Check
```powershell
Invoke-Command -ComputerName SEAIPSUTLv01 -ScriptBlock {
    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                                -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
        RestrictSendingNTLM  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic
        NtlmMinServerSec     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                                -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    }
}
```

### Event Log Check
```powershell
Invoke-Command -ComputerName SEAIPSUTLv01 -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $events = Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
    Write-Host "NTLM Warning/Error events (last 7 days): $($events.Count)"
    $events | Select-Object TimeCreated, Id, Message | Format-List
}
```

### secedit Export
```powershell
Invoke-Command -ComputerName SEAIPSUTLv01 -ScriptBlock {
    $f = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $f /quiet
    Select-String -Path $f -Pattern "LmCompatibilityLevel|NTLM"
    Remove-Item $f -Force
}
```

### Results
| Check | Expected | Actual | Status |
|---|---|---|---|
| LmCompatibilityLevel | 5 | | |
| RestrictSendingNTLMTraffic | 2 | | |
| NtlmMinServerSec | 537395200 | | |
| NTLM Event Errors (7d) | 0 | | |

---

## All-Servers Quick Summary Script

Run this to get a single consolidated view across all 6 servers at once:

```powershell
$servers = @("SEAFTPv01","SEASCOMMGTv03","SEASCOMRPTv01","SQLSLv01","DELLOMEFLSv01","SEAIPSUTLv01")

Invoke-Command -ComputerName $servers -ErrorAction SilentlyContinue -ScriptBlock {
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
    $ntlmErrors = (Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error","Warning") -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }).Count

    $lm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
           -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
    $rs = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
           -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic

    [PSCustomObject]@{
        Server              = $env:COMPUTERNAME
        LmLevel             = if ($null -eq $lm) { "NOT SET" } else { $lm }
        LmOK                = ($lm -eq 5)
        RestrictSending     = if ($null -eq $rs) { "NOT SET" } else { $rs }
        RestrictOK          = ($rs -eq 2)
        NTLMErrors7d        = $ntlmErrors
        OverallStatus       = if ($lm -eq 5 -and $rs -eq 2 -and $ntlmErrors -eq 0) { "CLEAN" } else { "NEEDS REVIEW" }
    }
} | Select-Object Server, LmLevel, LmOK, RestrictSending, RestrictOK, NTLMErrors7d, OverallStatus |
  Sort-Object OverallStatus, Server |
  Format-Table -AutoSize
```

---

## Overall Status Tracker

| Server | Policy Applied | LmLevel OK | RestrictSending OK | NTLM Events | Status |
|---|---|---|---|---|---|
| SEAFTPv01 | ✅ | | | | ⏳ Pending Check |
| SEASCOMMGTv03 | ✅ | | | | ⏳ Pending Check |
| SEASCOMRPTv01 | ✅ | | | | ⏳ Pending Check |
| SQLSLv01 | ✅ | | | | ⏳ Pending Check |
| DELLOMEFLSv01 | ✅ | ✅ | ✅ | 🔴 50+ | 🔴 Investigating |
| SEAIPSUTLv01 | ✅ | | | | ⏳ Pending Check |
