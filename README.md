# Microsoft Sentinel–Based SOC Attack Simulation and Investigation

## Project Overview
This project demonstrates a Security Operations Center (SOC) investigation workflow using Microsoft Sentinel and an Azure Windows Virtual Machine. It focuses on simulating controlled security activities, analyzing Windows Security Events, and developing detection logic using Kusto Query Language (KQL).

## Objectives
- Configure a cloud-based security monitoring environment.
- Collect and investigate Windows Security Events.
- Simulate controlled authentication and account-related activities.
- Develop KQL queries and Microsoft Sentinel Analytics Rules.
- Analyze event timelines and recommend incident-response actions.

## Technologies Used
- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Kusto Query Language (KQL)
- Windows Security Events
- Sysmon

## Security Scenarios
- Failed and successful login attempts
- Password-spray simulation
- User account creation
- Privilege escalation investigation
- Process and PowerShell activity
- File creation
- DNS and network activity
- Account lockout
- Scheduled-task creation
- Security audit log clearing investigation

## Sample KQL Detection Query

```kusto
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, Account,
          SubjectUserName, TargetUserName, Activity
| order by TimeGenerated desc
```

This query identifies Windows user-account creation events for further investigation.

## Key Learning Outcomes
- Security monitoring and log analysis
- KQL-based threat detection
- Windows Security Event investigation
- Analytics Rule configuration
- Incident investigation and response planning

## Project Report
See [`EH_6253_LabProject.pdf`](EH_6253_LabProject.pdf) for the documented lab setup, attack simulations, queries, and observations.

## Disclaimer
This project was conducted for educational purposes in an authorized lab environment. Security events should be investigated in context before being classified as malicious.

## References
- [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview)
- [Kusto Query Language](https://learn.microsoft.com/en-us/kusto/query/)
- [Windows Security Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/)
