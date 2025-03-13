# 🛡️ Incident Response Report: Impossible Travel Alert (NIST 800-61 Compliant)

---

## 1. Overview & Explanation
A security alert was triggered in **Azure Sentinel** due to **“Impossible Travel”** activity on a user account. Impossible travel alerts typically arise when a single user attempts logins from geographically distant locations within a short timeframe—beyond realistic physical travel speed. Although such alerts can indicate **credential compromise**, they can also be triggered by legitimate situations (e.g., VPN usage).

In this incident, multiple login attempts were detected for:
f0da900fd11f524a8d5a31634870658f585d4f17fb5f147254b8a07dad50b7ae@company.com

Logins occurred within approximately **1.5 hours** from **Marcham (Oxfordshire)**, **Reading**, and **Haringey (Greater London)**. While all locations are in the UK, the rapid pattern of logins flagged Sentinel’s Impossible Travel rule.

Following **NIST 800-61** guidelines, the security team validated the alert, contained risks if necessary, analyzed whether the event represented malicious or benign behavior, and updated detection rules to reduce false positives going forward.

---

## 2. Detection & Alert Rule Creation
### 2.1 Sentinel Alert Configuration
**Alert Name**: “Impossible Travel Alert”  
**Condition**: Detects a user logging in from distances/timeframes that violate corporate travel policy.  
**Data Source**: **SigninLogs** within Azure Sentinel (Log Analytics).

```kusto
let TimePeriodThreshold = timespan(7d); // Time range to look back
SigninLogs
| where UserPrincipalName == "f0da900fd11f524a8d5a31634870658f585d4f17fb5f147254b8a07dad50b7ae@company.com"
| where TimeGenerated > ago(TimePeriodThreshold)
| project TimeGenerated, UserPrincipalName, UserId, 
          City = tostring(parse_json(LocationDetails).city), 
          State = tostring(parse_json(LocationDetails).state), 
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

Result: An incident was raised in Sentinel, alerting security staff that a user was potentially traveling or spoofed across multiple locations too quickly to be legitimate.

## 3. Incident Analysis
### 3.1 Observed Login Locations & Timeline
Locations:

📍 Marcham, Oxfordshire, GB

📍 Reading, Reading, GB

📍 Haringey, Greater London, GB

Time Window: Approximately 1.5 hours apart (Determined by Google Maps).

Despite being in the same country, the policy defines a threshold for normal vs. suspicious travel times. 

Each sign-in was close enough to be plausible, yet triggered the rule meant to catch more extreme distance anomalies.

### 3.2 Case A: True Positive (Policy Violation)
Findings: The user’s activity violated corporate sign-in policy for “acceptable travel.”

#### Immediate Actions:

Disabled the user’s account in Active Directory (AD) and Azure AD.

Notified the user’s manager of potential policy violation.

Inspected logs for lateral movement or malicious pivoting:

```
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<OiD>"
```

Next Steps:

Determine if a legitimate reason existed (VPN usage, multi-site travel).

Propose geofencing (IP-based restrictions) to align with corporate policy.
## 3.3 Case B: False Positive (Benign Activity)
Findings: Logins from legitimate, nearby locations—travel time was feasible and user’s job responsibilities required frequent local commuting.

Resolution:

Alert deemed false positive; no further action was taken.

Activity matched user’s known routine within corporate guidelines.

### 3.4 Improving Impossible Travel Detection Rule

Below are techniques to reduce false positives:

- Exclude Known VPN IPs
  
Filters out logins through the organization’s recognized VPN gateways.

- Increase Distance Threshold
  
Adjust the maximum allowed distance for multiple sign-ins to better reflect user travel patterns.

- Filter by Business Hours
  
Restrict detection to unusual times if corporate policy requires.

- Exclude Specific Roles
  
Allows traveling executives or global admins to circumvent standard distance checks.

- Historical Travel Pattern Exclusion
  
Compares logins against the user’s typical city pattern to avoid repeated false alerts.

- Conditional Access Integration

Enforce stricter authentication (MFA) for high-risk or suspicious sign-in attempts.
## 4. Containment, Eradication & Recovery
Depending on whether the alert was confirmed malicious (Case A) or benign (Case B), the following NIST 800-61 phases were applied:

### 4.1 Containment (If Malicious)
- Disable the user’s account enterprise-wide.
- Revoke active sessions to immediately stop suspicious activity.
- Isolate any endpoints suspected of compromise to prevent lateral movement.
### 4.2 Eradication
- Reset credentials of the compromised account.
- Audit all user accounts for unauthorized access or group membership changes.
- Monitor high-value assets for follow-up infiltration attempts.
### 4.3 Recovery
- Verify system integrity (endpoint & cloud services) via EDR solutions.
- Conduct a thorough security audit to confirm no remaining compromise.
- Document any forensic or remediation actions for compliance.

## 5. Post-Incident Activities
#### Lessons Learned
Review impossible travel detection thresholds regularly (e.g., refining allowed distances, recognized VPN IPs).

Streamline automatic responses for faster triage of real threats.

Assess user policies around multi-location sign-ins, especially for traveling or hybrid workforce.

Policy Enhancements

Geo-Blocking/Geofencing for off-region logins.

MFA Enforcement across all remote sessions.

Conditional Access Policies that adapt sign-in rules based on user risk score, location, or device compliance.

#### Incident Closure
If malicious, ensure full scope and root cause analysis are completed.

If benign, label the alert as “false positive” for future reference.

## 6. Conclusion
An Impossible Travel Alert triggered in Sentinel showed rapid sign-in events for a single user across multiple UK locations. Applying **NIST 800-61** guidelines, the security team investigated whether it was a true positive policy violation (requiring account disablement and manager notification) or a false positive benign scenario. Updated detection thresholds and conditional access policies were recommended to reduce future false alerts and expedite response to genuine malicious behavior.

## 7. MITRE ATT&CK TTPs
**T1078: Valid Accounts** - Potential misuse of valid credentials (if compromised) to log in from unusual locations.

**PR.DS-5 (Data Protection)** – Detect & respond to suspicious account behaviors.

**PR.IP-8 (Response Plan)** – Strategies for handling policy violations.

**RS.CO-2 (Coordination)** – Involving stakeholders upon detection of suspicious activity.
