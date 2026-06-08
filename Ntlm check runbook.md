# NTLM Policy Checks Runbook
**Platform:** Tanium Enforce + Windows Servers  
**Scope:** GF Server - Prod Ring Zero Enforcement  
**Policy:** GF Server - Disable NTLM Authentication on Server  
**Last Updated:** 2026-06-08

---

## Overview

This runbook covers how to verify NTLM policy enforcement status across Windows servers managed by Tanium Enforce, how to detect NTLM-related errors in Windows event logs, and how to investigate and remediate blocked NTLM authentication attempts.

---

## 1. Verify Enforcement Status in Tanium Enforce

### 1.1 Check Policy Enforcement Dashboard

1. Log into the Tanium Console
2. Navigate to **Enforce → Enforcements**
3. Locate the enforcement: **GF Server - Prod Ring Zero Enforcement**
4. Review the **Enforcement Status** bar for the following states:

| Status | Meaning |
|---|---|
| **Applied** | Policy successfully written to the endpoint |
| **Partially Applied** | Some settings applied, others failed |
| **Not Applied** | Enforcement has not run or failed silently |
| **Error** | Enforcement ran but hit an explicit error |
| **Unsupported** | Policy setting not supported on that OS version |

5. Click into any endpoint showing **Error** or **Not Applied** and read the **State Reason** — this is the fastest path to root cause.

### 1.2 Common Enforce Error Reasons for Security Policies

| Error Reason | Likely Cause |
|---|---|
| `Unable to configure system with new security policy – Error code 1` | Registry conflict or OS incompatibility |
| `Enforcement tools not installed` | Tanium Enforce tools package not deployed to endpoint yet |
| `Policy conflict` | A GPO is overriding the Enforce-managed setting |
| `Access denied` | Tanium Client lacks rights to write the security policy |

### 1.3 Bulk Status Check via Tanium Interact

Run these sensors in the **Interact** module to check status across all servers at once:

```
Get Enforce - Enforcement Status from all machines with Is Windows Server equals true
Get Enforce - Enforcement State Reason from all machines with Is Windows Server equals true
```

---

## 2. Verify NTLM Registry Settings via PowerShell

### 2.1 Check a Single Server

```powershell
# LM Compatibility Level (key setting)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"

# Full NTLM settings check
$settings = @{
    "LmCompatibilityLevel"       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    "NtlmMinClientSec"           = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    "NtlmMinServerSec"           = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    "RestrictSendingNTLMTraffic" = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    "AuditReceivingNTLMTraffic"  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
}

foreach ($name in $settings.Keys) {
    $val = (Get-ItemProperty -Path $settings[$name] -Name $name -ErrorAction SilentlyContinue).$name
    Write-Host "$name = $val"
}
```

### 2.2 Check All Servers Remotely

```powershell
$servers = @(
    "SEAFTPv01",
    "SEASCOMMGTv03",
    "SEASCOMRPTv01",
    "SQLSLv01",
    "DELLOMEFLSv01",
    "SEAIPSUTLv01"
)

Invoke-Command -ComputerName $servers -ErrorAction SilentlyContinue -ScriptBlock {

    $lmLevel        = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                       -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel
    $minClient      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                       -Name "NtlmMinClientSec" -EA SilentlyContinue).NtlmMinClientSec
    $minServer      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                       -Name "NtlmMinServerSec" -EA SilentlyContinue).NtlmMinServerSec
    $restrictSend   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                       -Name "RestrictSendingNTLMTraffic" -EA SilentlyContinue).RestrictSendingNTLMTraffic

    $ntlmErrors = 0
    try {
        wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true 2>$null
        $ntlmErrors = (Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -EA SilentlyContinue |
            Where-Object {
                $_.LevelDisplayName -in @("Error","Warning") -and
                $_.TimeCreated -gt (Get-Date).AddHours(-24)
            }).Count
    } catch { $ntlmErrors = 0 }

    $lmStatus = switch ($lmLevel) {
        5       { "NTLM Disabled (Level 5)" }
        4       { "NTLMv2 Only (Level 4)" }
        3       { "NTLMv2 Only (Level 3)" }
        default { "WEAK or NOT SET (Level $lmLevel)" }
    }

    [PSCustomObject]@{
        Server               = $env:COMPUTERNAME
        LmCompatibilityLevel = if ($null -eq $lmLevel) { "NOT SET" } else { $lmLevel }
        LmStatus             = $lmStatus
        NtlmMinClientSec     = if ($null -eq $minClient) { "NOT SET" } else { $minClient }
        NtlmMinServerSec     = if ($null -eq $minServer) { "NOT SET" } else { $minServer }
        RestrictSendingNTLM  = if ($null -eq $restrictSend) { "NOT SET" } else { $restrictSend }
        NTLMErrorsLast24hrs  = $ntlmErrors
    }

} | Select-Object Server, LmCompatibilityLevel, LmStatus, NtlmMinClientSec, NtlmMinServerSec, RestrictSendingNTLM, NTLMErrorsLast24hrs |
  Sort-Object Server |
  Format-Table -AutoSize
```

### 2.3 Expected Values

| Registry Value | Expected | Concern |
|---|---|---|
| `LmCompatibilityLevel` | `5` | Anything below `3` |
| `NtlmMinClientSec` | `537395200` | `NOT SET` |
| `NtlmMinServerSec` | `537395200` | `NOT SET` |
| `RestrictSendingNTLMTraffic` | `2` (Deny all) | `0` or `NOT SET` |

### 2.4 Verify via secedit (Effective Policy Export)

```powershell
$outFile = "$env:TEMP\secpol_check.cfg"
secedit /export /cfg $outFile /quiet
Select-String -Path $outFile -Pattern "LmCompatibilityLevel|NTLM"
```

---

## 3. Check NTLM Event Logs for Errors

### 3.1 Enable the NTLM Operational Log (if not already on)

```powershell
wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true
```

### 3.2 Key Event IDs

| Event ID | Log | Meaning |
|---|---|---|
| **4002** | NTLM/Operational | Incoming NTLM traffic blocked on this server |
| **4004** | NTLM/Operational | Outgoing NTLM traffic blocked from this server |
| **8001** | NTLM/Operational | NTLM authentication blocked (client side) |
| **4776** | Security | NTLM credential validation attempt (success or failure) |
| **4624** | Security | Successful logon — filter on AuthPackage = NTLM to find NTLM sessions |
| **4625** | Security | Failed logon — indicates blocked NTLM auth causing access failure |

### 3.3 Query NTLM Warnings and Errors

```powershell
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 100 |
    Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List
```

### 3.4 Get Detailed XML from NTLM Events

```powershell
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 20 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        EventId      = $_.Id
        CallingHost  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CallingProcessName" }).'#text'
        UserIdentity = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CallingProcessUserIdentity" }).'#text'
        TargetServer = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetName" }).'#text'
    }
} | Format-Table -AutoSize
```

### 3.5 Correlate with Security Log (Find Source Workstation)

```powershell
# Replace SOURCEHOSTNAME with the machine name seen in NTLM events
Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4625 or EventID=4624] and EventData[Data[@Name='WorkstationName']='SOURCEHOSTNAME']]" `
  -MaxEvents 20 |
  Select-Object TimeCreated, Id,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}},
    @{N='AuthPackage';E={$_.Properties[10].Value}},
    @{N='Workstation';E={$_.Properties[11].Value}} |
  Format-Table -AutoSize
```

---

## 4. Investigate the Source of NTLM Attempts

When Event ID 4002 appears repeatedly from a specific machine account (e.g., `MACHINENAME$`), follow these steps to identify the process responsible.

### 4.1 Identify the Process by PID

```powershell
# Run on the SOURCE machine
Get-Process -Id <PID>
Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq <PID> } |
    Select-Object Name, DisplayName, StartName
```

### 4.2 Check for Monitoring/Agent Services

```powershell
Get-Service | Where-Object {
    $_.DisplayName -match "Dell|OMSA|OpenManage|SCOM|Monitor|HealthService|WMI|SNMP|NewRelic|Tanium"
} | Select-Object Name, DisplayName, Status
```

### 4.3 Check Active Network Connections

```powershell
Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -notmatch "^(127|::)" } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        @{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
        OwningProcess |
    Sort-Object RemoteAddress |
    Format-Table -AutoSize
```

### 4.4 Check SMB Connections and Mapped Drives

```powershell
Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect
Get-WmiObject Win32_MappedLogicalDisk | Select-Object Name, ProviderName
net use
```

---

## 5. Remediation Options

### 5.1 Add an NTLM Server Exception (for legitimate services)

If a specific service legitimately requires NTLM (e.g., SCOM, legacy monitoring agents), add a server exception in the Tanium Enforce policy rather than disabling the restriction entirely.

The Group Policy path is:  
`Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`  
Setting: **Network Security: Restrict NTLM: Add server exceptions**

Add the target server's NetBIOS name to the exception list, one per line. Wildcards (`*`) are supported.

### 5.2 Verify Existing NTLM Exceptions

```powershell
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
 -Name "ClientAllowedNTLMServers" -ErrorAction SilentlyContinue).ClientAllowedNTLMServers
```

### 5.3 Fix Kerberos (Preferred Long-Term Fix)

NTLM fallback usually happens when Kerberos fails due to one of these causes:

- Missing or incorrect SPN registration on the target server
- DNS resolution failure (machine connecting by IP instead of hostname)
- Clock skew greater than 5 minutes between machines
- Service account not trusted for Kerberos delegation

```powershell
# Check SPNs registered for a server
setspn -L SERVERNAME

# Check for duplicate SPNs (common Kerberos failure cause)
setspn -X
```

---

## 6. Servers in Scope

| Server | Role | Notes |
|---|---|---|
| SEAFTPv01 | FTP Server | |
| SEASCOMMGTv03 | SCOM Management | |
| SEASCOMRPTv01 | SCOM Reporting | |
| SQLSLv01 | SQL Server | |
| DELLOMEFLSv01 | Dell License/Monitoring Server | Active NTLM block events — see separate investigation doc |
| SEAIPSUTLv01 | IPS Utility Server | |

---

## 7. References

- Tanium Enforce User Guide: https://help.tanium.com/bundle/ug_enforce_onprem/page/enforce/troubleshooting.html
- Microsoft NTLM Audit Group Policy: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/jj865672(v=ws.10)
- Network Security Restrict NTLM Policy Settings: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain
