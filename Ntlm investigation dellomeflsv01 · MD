# NTLM Investigation Results — DELLOMEFLSv01
**Date:** 2026-06-08  
**Investigated By:** GF Server Team  
**Policy:** GF Server - Disable NTLM Authentication on Server (Tanium Enforce)  
**Status:** 🔴 Active NTLM Block Events — Investigation In Progress

---

## Summary of Findings

DELLOMEFLSv01 is generating repeated **Event ID 4002** warnings on this server — incoming NTLM authentication attempts that are being blocked by the Tanium Enforce policy. The policy is working correctly; the issue is that a process on DELLOMEFLSv01 is still attempting NTLM authentication instead of Kerberos.

---

## Enforcement Status

| Check | Result |
|---|---|
| Tanium Enforce Status | ✅ Applied |
| Policy Version | 2 |
| Enforcement Created | 6/5/2026 2:33 PM PDT |
| `LmCompatibilityLevel` | Confirmed enforced |
| `RestrictSendingNTLMTraffic` | `2` (Deny all outbound NTLM) ✅ |

The policy **is applied** on DELLOMEFLSv01. Outbound NTLM restriction is set to `2` (Deny all), which is the correct enforced value.

---

## Event Log Evidence

**Log:** `Microsoft-Windows-NTLM/Operational`  
**Event ID:** 4002  
**Level:** Warning  
**Volume:** 50+ events observed in a ~2 hour window on 2026-06-08

### Sample Event
```
TimeCreated      : 6/8/2026 12:13:43 PM
Id               : 4002
LevelDisplayName : Warning
Message          : NTLM server blocked: Incoming NTLM traffic to servers that is blocked
                   Calling process PID:           444
                   Calling process name:          C:\Windows\System32\svchost.exe
                   Calling process LUID:          0x3E4
                   Calling process user identity: DELLOMEFLSV01$
                   Calling process domain:        SEATTLE
```

### Key Observations

- **All events are identical** — same PID (444), same process (`svchost.exe`), same identity (`DELLOMEFLSV01$`)
- **Recurring pattern** — events fire every ~10-15 minutes consistently, suggesting a scheduled polling interval
- **Machine account** — `DELLOMEFLSV01$` is the machine's computer account, not a user account, indicating a service (not a user session) is making the connection
- **LUID 0x3E4** — this is the well-known LUID for the **Network Service** account

---

## Process Investigation

### PID 444 — Services Identified

```
Name             DisplayName               StartName
----             -----------               ---------
RpcEptMapper     RPC Endpoint Mapper       NT AUTHORITY\NetworkService
RpcSs            Remote Procedure Call     NT AUTHORITY\NetworkService
```

PID 444 is the **RPC service group** running as Network Service. This is a shared `svchost.exe` host process. The NTLM attempts are being made through RPC calls originating from this process group.

### HealthService (Microsoft Monitoring Agent)

```
Name      : HealthService
StartName : LocalSystem
ProcessId : 2976
State     : Running
```

The SCOM/MMA agent (`HealthService`) is running but uses `LocalSystem`, not Network Service — it is not the direct source of PID 444's NTLM calls. However it is actively connected to the SCOM management server:

```
10.10.2.83   52227   10.10.3.93   5723   HealthService   2976
```

Port `5723` = SCOM agent communication channel to management server at `10.10.3.93`.

---

## Network Connections on DELLOMEFLSv01

Active established connections at time of investigation:

| Local Port | Remote Address | Remote Port | Process | Notes |
|---|---|---|---|---|
| 49959 | 10.10.1.113 | 389 | svchost | LDAP — normal AD communication |
| 8289 | 10.10.2.56 | 20567 | svchost | Unknown — needs investigation |
| 49954 | 10.10.2.61 | 445 | System | **SMB — potential NTLM source** |
| 52227 | 10.10.3.93 | 5723 | HealthService | SCOM agent channel |
| 65170 | 162.247.241.2 | 443 | newrelic-infra | New Relic monitoring |
| 50280 | 162.247.243.20 | 443 | newrelic-infra | New Relic monitoring |
| 52275 | 20.59.87.227 | 443 | svchost | Azure/cloud service |
| 63899 | 40.112.242.140 | 443 | himds | Azure IMDS (Arc/hybrid) |
| 50254 | 40.64.132.128 | 443 | MetricsExtension.Native | Azure Monitor |
| 63931 | 52.11.76.40 | 17472 | TaniumClient | Tanium cloud connection ✅ |

### ⚠️ High Priority — SMB Connection to 10.10.2.61 (Port 445)

The `System` account has an active **SMB connection** to `10.10.2.61:445`. SMB connections from the System/machine account are a well-known source of NTLM fallback when Kerberos cannot be negotiated. This is the most likely candidate for the NTLM block events.

**Next step:** Resolve `10.10.2.61` to a hostname and determine why DELLOMEFLSv01 is making an SMB connection to it.

---

## Security Log Findings

Logon events from DELLOMEFLSv01 found in the Security log:

| Time | Event | User | Logon Type | Auth Package | Result |
|---|---|---|---|---|---|
| 6/8/2026 12:12:38 PM | 4624 | fritzraprd | 10 (RemoteInteractive) | Negotiate | ✅ Success |
| 6/6/2026 9:58:47 AM | 4624 | genesisboprd | 2 (Interactive) | Negotiate | ✅ Success |
| 6/6/2026 9:58:40 AM | 4625 | genesisboprd | 2 (Interactive) | — | ❌ Failed |
| 5/28/2026 1:38:43 AM | 4624 | jamesdiprd | 10 (RemoteInteractive) | Negotiate | ✅ Success |

**Note:** User logons from DELLOMEFLSv01 are using **Negotiate** (Kerberos), not NTLM — these are not the source of the 4002 events. The problem is service-level machine account authentication, not user logons.

---

## Services Running on DELLOMEFLSv01

| Service | Status | Notes |
|---|---|---|
| HealthService (Microsoft Monitoring Agent) | ✅ Running | SCOM agent — connected to 10.10.3.93:5723 |
| newrelic-infra | ✅ Running | New Relic infrastructure agent |
| himds | ✅ Running | Azure Arc/Hybrid Instance Metadata |
| MetricsExtension.Native | ✅ Running | Azure Monitor metrics |
| TaniumClient | ✅ Running | Tanium client — connected to cloud |
| AdtAgent (MMA Audit Forwarding) | ⭕ Stopped | |
| SNMPTRAP | ⭕ Stopped | |
| wmiApSrv (WMI Performance Adapter) | ⭕ Stopped | |

---

## Outstanding Investigation Steps

- [ ] Resolve `10.10.2.61` to hostname — `Resolve-DnsName 10.10.2.61`
- [ ] Determine why DELLOMEFLSv01 has an SMB connection to `10.10.2.61` (drive map, DFS, service?)
- [ ] Confirm whether `10.10.2.61` is one of the other 5 servers in scope
- [ ] Check SMB connections and mapped drives on DELLOMEFLSv01
- [ ] Determine if SCOM management server at `10.10.3.93` requires an NTLM exception
- [ ] Verify SPN registration for servers DELLOMEFLSv01 connects to

---

## Recommended Remediation

### Option 1 — Short Term: Add NTLM Exception for SMB Target
If `10.10.2.61` is a server that legitimately requires machine account access from DELLOMEFLSv01, add it to the NTLM server exception list in the Tanium Enforce policy.

### Option 2 — Long Term: Fix Kerberos for SMB Connection
Ensure the target server (`10.10.2.61`) has a valid SPN registered and that DELLOMEFLSv01 connects to it by **hostname**, not IP address. NTLM is always used when connecting by IP — switching to hostname allows Kerberos negotiation.

```powershell
# Check SPNs on the target server
setspn -L <HOSTNAME_OF_10.10.2.61>

# Check for duplicate SPNs
setspn -X
```

---

## Commands Run During Investigation

```powershell
# 1. Check NTLM Operational log for warnings/errors
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 50 |
    Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# 2. Identify process behind PID 444
Get-Process -Id 444 | Select-Object Name, Id
Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq 444 } |
    Select-Object Name, DisplayName, StartName

# 3. Get XML detail from NTLM events
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 10 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        CallingHost  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CallingProcessName" }).'#text'
        UserIdentity = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CallingProcessUserIdentity" }).'#text'
        TargetServer = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetName" }).'#text'
    }
}

# 4. Check RestrictSendingNTLMTraffic on DELLOMEFLSv01
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
     -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
}

# 5. Check Security log for logons from DELLOMEFLSv01
Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4625 or EventID=4624] and EventData[Data[@Name='WorkstationName']='DELLOMEFLSv01']]" `
  -MaxEvents 20 | Select-Object TimeCreated, Id,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}},
    @{N='AuthPackage';E={$_.Properties[10].Value}},
    @{N='Workstation';E={$_.Properties[11].Value}} | Format-Table -AutoSize

# 6. Check services on DELLOMEFLSv01
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    Get-Service | Where-Object {
        $_.DisplayName -match "Dell|OMSA|OpenManage|DSM|Systems Management|WMI|SNMP|Monitor"
    } | Select-Object Name, DisplayName, Status
}

# 7. Check network connections on DELLOMEFLSv01
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    Get-NetTCPConnection -State Established |
        Where-Object { $_.RemoteAddress -notmatch "^(127|::)" } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
            @{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
            OwningProcess | Sort-Object RemoteAddress | Format-Table -AutoSize
}

# 8. Confirm HealthService account
Invoke-Command -ComputerName DELLOMEFLSv01 -ScriptBlock {
    $svc = Get-WmiObject Win32_Service -Filter "Name='HealthService'"
    [PSCustomObject]@{
        Name = $svc.Name; StartName = $svc.StartName
        ProcessId = $svc.ProcessId; State = $svc.State
    }
}
```
