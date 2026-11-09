# Microsoft Sentinel – SOC Attack Simulation and Investigation

## Project Overview

This project demonstrates a hands-on Security Operations Center (SOC) investigation using **Microsoft Sentinel**. It focuses on simulating controlled security activities on a Windows virtual machine, collecting Windows Security Events, and analyzing them using Kusto Query Language (KQL).

The project uses Microsoft Azure services to understand how security events are collected, monitored, investigated, and detected in a cloud-based SIEM environment.

## Objectives

- Set up Microsoft Sentinel and an Azure Windows Virtual Machine.
- Configure Azure Monitor Agent (AMA) and a Data Collection Rule (DCR).
- Collect and analyze Windows Security Events.
- Simulate common security activities in a controlled environment.
- Investigate security events using KQL queries.
- Configure an analytics rule to detect repeated failed login attempts.
- Understand the SOC investigation process and document findings.

## Technologies Used

| Technology | Purpose |
|---|---|
| Microsoft Azure | Cloud environment |
| Microsoft Sentinel | SIEM and security monitoring |
| Azure Virtual Machine | Windows endpoint for simulations |
| Log Analytics Workspace | Security log storage and analysis |
| Azure Monitor Agent (AMA) | Collects Windows security events |
| Data Collection Rule (DCR) | Configures event collection |
| Kusto Query Language (KQL) | Security event investigation |
| Sysmon | Local endpoint activity monitoring |
| Windows PowerShell | User management and activity simulation |

## Project Architecture and Workflow

The project follows this workflow:

1. **Azure Virtual Machine:** Created a Windows virtual machine to perform controlled security simulations.
2. **Log Analytics Workspace:** Created a workspace to store and analyze collected security logs.
3. **Microsoft Sentinel:** Connected Sentinel to the Log Analytics Workspace.
4. **Azure Monitor Agent:** Installed and configured AMA on the Windows VM.
5. **Data Collection Rule:** Configured a DCR to collect Windows Security Events.
6. **Attack Simulation:** Generated controlled security events on the Windows VM.
7. **KQL Investigation:** Used KQL queries to investigate collected events and identify suspicious activities.
8. **Analytics Rule:** Configured a rule to detect repeated failed login attempts.
9. **Documentation:** Recorded the simulation steps, observations, queries, and investigation results.

**Workflow:**

Windows Virtual Machine → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel → KQL Investigation → Analytics Rule and Alerts

## Security Scenarios Investigated

The following security activities were simulated and investigated as part of the project.

| Event ID | Security Activity |
|---|---|
| 4625 | Failed Login Attempts |
| 4624 | Successful Login |
| 4720 | User Account Creation |
| 4732 | User Added to a Local Security Group |
| 4672 | Special Privileges Assigned to a Logon |
| 4740 | Account Lockout |
| 4698 | Scheduled Task Creation |
| 1102 | Security Audit Log Cleared |

### Sysmon-Based Endpoint Investigation

Additional endpoint activities were investigated locally using Sysmon and Windows Event Viewer.

| Sysmon Event ID | Activity |
|---|---|
| 1 | Process Creation |
| 11 | File Creation |
| 22 | DNS Query |
| 12–14 | Registry Changes |

**Note:** The Sysmon activities were investigated locally on the Windows VM. Their ingestion into Microsoft Sentinel was not verified as part of this project.

## Sample KQL Detection Queries

### 1. Failed Login Attempts

Identifies failed login attempts recorded in Windows Security Events.

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, Computer
| order by TimeGenerated desc
```

### 2. Multiple Failed Login Attempts

Identifies accounts and IP addresses with five or more failed login attempts within a five-minute period.

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count()
    by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by TimeGenerated desc
```

### 3. User Account Creation

Identifies newly created user accounts.

```kusto
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, Computer
| order by TimeGenerated desc
```

### 4. Privilege and Group Membership Changes

Identifies changes to local security group membership.

```kusto
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Account, Computer, Activity
| order by TimeGenerated desc
```

### 5. Security Audit Log Cleared

Identifies events related to clearing the Windows Security audit log.

```kusto
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Account, Computer
| order by TimeGenerated desc
```

## Microsoft Sentinel Analytics Rule

Configured an analytics rule named **Failed Login Detection** to identify repeated failed Windows login attempts.

- **Rule Name:** Failed Login Detection
- **Description:** Detects multiple failed Windows login attempts.
- **Event ID:** 4625
- **Threshold:** Five or more failed attempts
- **Query Frequency:** Every 5 minutes
- **Lookup Period:** Last 5 minutes
- **Severity:** Medium

The rule generates alerts when the configured query identifies matching activity.

## Key Learning Outcomes

Through this project, I gained practical experience in:

- Configuring Microsoft Sentinel in Microsoft Azure.
- Connecting Windows endpoints to a Log Analytics Workspace.
- Collecting security events using Azure Monitor Agent and DCR.
- Simulating and investigating Windows security activities.
- Writing KQL queries for security event analysis.
- Understanding account-related and privilege-related security events.
- Configuring analytics rules and understanding alert generation.
- Performing basic SOC investigation and documenting findings.

## Project Report

The complete project documentation includes the Azure setup, VM configuration, event simulations, KQL investigations, analytics rule configuration, screenshots, observations, and conclusions.

**Project Report:** [EH_6253_LabProject.pdf](EH_6253_LabProject.pdf)

## Disclaimer

This project was performed for educational purposes in a controlled lab environment. All security activities were simulated on the configured Windows virtual machine. The project does not involve unauthorized access to real systems or networks.

## References

- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Azure Monitor Agent Documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Kusto Query Language Documentation](https://learn.microsoft.com/en-us/kusto/query/)
- [Windows Security Auditing Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-policy-recommendations)
