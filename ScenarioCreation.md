# Threat Event: Impossible Travel Sign-In

**Rapid, Multi-Location Logins for a Single User Account**

---

## Steps the "Bad Actor" Took to Create Logs & IoCs
In this scenario, we simulate an adversary (or potentially benign user situation) causing **Impossible Travel** alerts:

1. **Obtain or Use Valid Credentials**  
   The attacker acquires the user’s credentials (or the user themselves logs in) from multiple UK locations within a short timeframe, raising suspicion in **SigninLogs**.

2. **Initiate Multiple Logins**  
   The user’s credentials are used to authenticate from:
   - Marcham, Oxfordshire, GB  
   - Reading, Reading, GB  
   - Haringey, Greater London, GB  
   All within ~1.5 hours.

3. **Trigger Sentinel “Impossible Travel” Rule**  
   Due to corporate travel policy thresholds, **Azure Sentinel** flags the logins as anomalous. This creates an **incident** for analysis.

4. **Potential Pivot / Malicious Behavior** (Case A)  
   If truly malicious, the adversary may then attempt to:
   - Enumerate Azure resources via `AzureActivity`
   - Access sensitive SharePoint sites or corporate data
   - Modify or escalate privileges in Azure AD

5. **Benign Explanation** (Case B)  
   Alternatively, the user might be traveling locally, using a VPN, or working from multiple branches. This results in a **false positive** if all access points prove legitimate.

---

## Tables Used to Detect IoCs

| **Parameter** | **Description**                                                                                                                      |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Name**      | SigninLogs                                                                                                                           |
| **Info**      | [MS Docs: SigninLogs Table](https://learn.microsoft.com/azure/active-directory/reports-monitoring/reference-azure-monitor-queries)   |
| **Purpose**   | Tracks user login events, IP addresses, location details, and timestamps. Used to detect anomalies in travel speed or location.      |

| **Parameter** | **Description**                                                                                                               |
|---------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Name**      | AzureActivity                                                                                                                 |
| **Info**      | [MS Docs: Azure Activity Table](https://learn.microsoft.com/azure/azure-monitor/reference)                                     |
| **Purpose**   | Logs changes and administrative actions in Azure. May reveal lateral movement or malicious pivoting after compromised sign-in. |

---

## Related Queries

```kql
// Impossible Travel Detection Query
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where UserPrincipalName == "f0da900fd11f524a8d5a31634870658f585d4f17fb5f147254b8a07dad50b7ae@company.com"
| where TimeGenerated > ago(TimePeriodThreshold)
| project TimeGenerated, UserPrincipalName, UserId, 
          City = tostring(parse_json(LocationDetails).city), 
          State = tostring(parse_json(LocationDetails).state), 
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

```
// Investigate Azure Activity for Potential Lateral Movement
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<OiD>"
```

```
// Example Extension: Known VPN Exclusions
let KnownVPNs = dynamic(["203.0.113.10", "198.51.100.25"]);
SigninLogs
| where not(IPAddress in (KnownVPNs))
```

# Possible Outcomes
## Case A: True Positive

### Account Disabled in AD & AAD
- Manager & Security alerted; logs reviewed for further compromise
- Recommendations: Implement geofencing, check for compromised credentials
## Case B: False Positive

- Travel or Local Commute explains multiple sign-ins
- No additional action required, Alert Marked Benign
- Tuning detection thresholds (distance/time or known VPN IPs) to reduce future false positives
## NIST 800-61 Alignment
### Preparation
Have Sentinel alerts configured for impossible travel detection

Maintain user awareness of geo-based anomalies

Detection & Analysis

Investigate SigninLogs for location-based anomalies

Differentiate malicious vs. benign multi-location logins (Case A vs. Case B)

### Containment, Eradication & Recovery

Contain by disabling the account, revoking sessions, isolating endpoints if malicious

Eradicate by resetting credentials, auditing user accounts

Recover by verifying system integrity, enabling multi-factor authentication, implementing geofencing

### Post-Incident Activity

#### Lessons Learned: Evaluate detection thresholds & conditional access settings
#### Policy Updates: Possibly raise or refine distance/time sensitivity; incorporate recognized VPN addresses
## Summary
This scenario walks through an Impossible Travel detection in Azure Sentinel, where a single user’s credentials were used (legitimately or maliciously) from multiple UK locations in a short span. 

The resulting alerts prompted immediate investigation following **NIST 800-61** steps. 

Determining whether it was a true compromise or benign user activity leads to different response paths, highlighting the importance of robust detection tuning, thorough incident analysis, and strong remediation policies.
