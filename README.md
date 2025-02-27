# Incident-Response_Impossible-Travel
Azure Sentinel Incident Response Impossible Travel Alert (NIST 800-161 Compliant)

# 🚨 Incident Response Report: Impossible Travel Alert (NIST 800-161 Compliant)

---

## 🛑 **Detection**

### **Incident Trigger**
An alert was raised for **impossible travel** involving the following account:

- **Account:** `f0da900fd11f524a8d5a31634870658f585d4f17fb5f147254b8a07dad50b7ae@company.com`

### **Observed Login Locations:**
- 📍 Marcham, Oxfordshire, GB  
- 📍 Reading, Reading, GB  
- 📍 Haringey, Greater London, GB  

### **Timeline of Events:**
- The timestamps of the logins were **consistent with realistic travel times** (all within an hour and a half from each other).

### **Detection Query (KQL):**
```kusto
let TimePeriodThreshold = timespan(7d); // Time range to look back
SigninLogs
| where UserPrincipalName == "f0da900fd11f524a8d5a31634870658f585d4f17fb5f147254b8a07dad50b7ae@company.com"
| where TimeGenerated > ago(TimePeriodThreshold)
| project TimeGenerated, UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), 
         State = tostring(parse_json(LocationDetails).state), 
         Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```


### NIST 800-161 Compliance:
- ID.AM-1: Inventory and tracking of user accounts.

- PR.DS-5: Implementation of data loss prevention measures for suspicious activities.

## 🔍 Analysis - Case A: True Positive (Policy Violation)
* The user logged in from multiple locations within travel distance but outside corporate policy for acceptable login behavior.

* The rapid pattern of location changes indicates a potential policy violation.

#### Immediate Actions Taken:

- Disabled the account in Active Directory (AD) and Azure Active Directory (AAD).

- Notified the user's manager regarding the policy violation.

- Inspected logs for pivoting or malicious activity using the following query:

``` kusto
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<OiD>"
```

#### Next Steps:
Investigate if the user has any legitimate reason for rapid location changes (e.g., VPN usage, multi-location business travel).

Suggest updating the corporate policy to include geofencing for added security.

### NIST 800-161 Compliance:
- PR.IP-8: Development of response strategies for detected policy violations.

- RS.CO-2: Coordination with internal stakeholders upon detection.

### MITRE ATT&CK TTP Assessment:

**T1078: Valid Accounts –** Potential misuse of valid credentials for unauthorized access.


### Response Plan: Mitigation & Prevention:

## Containment:

* Disable the user account across all systems.

* Revoke all active sessions associated with the affected user.

* Isolate any affected endpoints to prevent lateral movement.

## Eradication:

* Reset all credentials associated with the compromised account.

* Audit user accounts for any unauthorized access.

* Implement additional monitoring on high-value accounts for anomalous activity.

## Recovery:

* Verify system integrity using endpoint detection and response (EDR) tools.

* Conduct a full security audit.

## Prevention:

* Enforce multi-factor authentication (MFA) for all remote connections.

* Apply geo-blocking or geofencing to restrict logins to authorized regions.

* Regularly update and enforce conditional access policies based on user risk levels.

# Analysis - Case B: False Positive (Benign Activity)
* The login locations were within acceptable distances and time frames.

* The user's travel pattern appears consistent with expected behavior.

### Resolution:
* The alert was deemed a false positive.

* No further action was taken as the activity falls within corporate policy.

## Improving Impossible Travel Detection Rule (False Positive Reduction)
1. Exclude Known VPN IPs
``` kusto
let KnownVPNs = dynamic(["203.0.113.10", "198.51.100.25"]);
SigninLogs
| where UserPrincipalName == "<user_email>"
| where TimeGenerated > ago(7d)
| where not(IPAddress in (KnownVPNs))
```

2. Increase Distance Threshold
``` kusto
let DistanceThresholdKm = 100;
SigninLogs
| extend City = tostring(parse_json(LocationDetails).city),
         Latitude = todouble(parse_json(LocationDetails).geoCoordinates.latitude),
         Longitude = todouble(parse_json(LocationDetails).geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| extend PreviousLatitude = prev(Latitude),
         PreviousLongitude = prev(Longitude),
         PreviousTime = prev(TimeGenerated)
| extend GeoDistanceKm = geo_distance_2points(Latitude, Longitude, PreviousLatitude, PreviousLongitude)
| where GeoDistanceKm > DistanceThresholdKm
```

3. Filter by Business Hours (9 AM - 6 PM)
```kusto
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay between (9 .. 18)
```

4. Exclude Specific Roles
```kusto
let ExcludedRoles = dynamic(["Global Administrator", "Traveling Executive"]);
SigninLogs
| where UserPrincipalName !in (ExcludedRoles)
```

5. Historical Travel Pattern Exclusion
```kusto
let HistoricalThreshold = 30d;
let FrequentCities = 
SigninLogs
| where TimeGenerated > ago(HistoricalThreshold)
| summarize LoginCount = count() by UserPrincipalName, City
| where LoginCount > 10
| project UserPrincipalName, City;

SigninLogs
| where City !in (FrequentCities)
```

6. Conditional Access Integration
Enforce stricter authentication for high-risk logins using Azure Conditional Access policies.

### NIST 800-161 Compliance:

- DE.DP-4: Adjust detection processes to reduce false positives.

- PR.AC-7: Enforce least privilege and conditional access policies.

## Lessons Learned & Improvements

* Regularly review detection rules to align with current corporate travel policies.

* Automate response actions for true positives to reduce response time.
