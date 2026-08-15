
# Google SecOps (Chronicle) Curated Detections: Flaw Analysis & Tuning

This repository documents architectural flaws, systemic logic errors, and tuning recommendations for native **Google SecOps (Chronicle) Curated Detections**. 

While Google's Threat Intelligence (GCTI) provides excellent conceptual threat coverage (such as tracking APT29/BRICKSTORM campaigns), the raw YARA-L implementation of these curated rules often contains systemic design failures and fails to account for standard enterprise architectures. This leads to massive alert fatigue and useless false positives.

This project provides a technical breakdown of *why* certain rules fail in production and offers optimized Custom Rules to replace them.

---

## 📑 Table of Contents
1. [O365 Suite Alerting Failure for BRICKSTORM / APT29](#1-o365-suite-alerting-failure-for-brickstorm--apt29)
    - [Flaw 1: Grouping Logic Contradiction](#flaw-1-grouping-logic-contradiction)
    - [Flaw 2: Outlook Mobile Public Client Oversight](#flaw-2-outlook-mobile-public-client-oversight)
    - [Flaw 3: Shared Mailbox Collision](#flaw-3-shared-mailbox-collision)
    - [Tuned YARA-L Solutions](#tuned-yara-l-solutions-for-o365-rules)
2. [UEBA: Anomalous Auth Attempts Total](#2-ueba-anomalous-auth-attempts-total)
    - [Hardcoding Flaw & Alert Fatigue](#hardcoding-flaw--alert-fatigue)
    - [Tuning Recommendations](#ueba-tuning-recommendations)

---

## 1. O365 Suite Alerting Failure for BRICKSTORM / APT29

Google released a suite of rules to detect bulk email exfiltration from Microsoft 365 Exchange Online by compromised Service Principals ([techniques heavily used by APT29/Midnight Blizzard](https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign)). 

The affected curated rules are:
* `O365 Mailbox Access by Service Principal with Multiple User Agents`
* `O365 Multiple Mailboxes Accessed by Service Principal`
* `O365 Mailbox Access by Service Principal from Multiple ASNs`
* `O365 Multiple Mailboxes Accessed via Microsoft Graph API`

### ❌ Core Flaws in Google's Logic

This suite of rules contains systemic logic mismatches between the stated objective and the YARA-L implementation, likely due to code reuse across the rule pack. The rules fail to properly distinguish between automated Service Principals and standard human activity, resulting in alerts that trigger on normal employee behavior.

#### Flaw 1: Grouping Logic Contradiction
Despite the rule description explicitly stating: *"Detects a Service Principal with a single O365 session ID..."*, the YARA-L `match` section of the "Multiple User Agents" rule groups by `$application_id` instead of the session ID (`$session_id`). This completely contradicts the rule's stated objective, aggregating unrelated human logins over a 3-hour window simply because they use the same application. 

#### Flaw 2: Outlook Mobile Public Client Oversight
The rules track anomalous behavioral patterns (changing IPs, ASNs, or User-Agents) tied to a specific `ClientAppId`. While Google includes an exclusion regex for several native Microsoft applications, they inexplicably omitted the most ubiquitous human mobile client: the **Microsoft Outlook Mobile App** (`27922004-5251-4030-b22d-91ecd9a37ea4`).
* **Impact:** Without filtering out this Public Client, legitimate employees reading shared mailboxes from their smartphones who move between networks (e.g., switching from Wi-Fi to 4G) inherently trigger the `Multiple ASNs` and `Multiple IPs` alerts. Different employees using iOS and Android to check the same departmental mailbox trigger the `Multiple User Agents` alert.

#### Flaw 3: Shared Mailbox Collision
To identify backend service accounts, Google's logic relies on this condition:
`$e.principal.user.userid != $e.target.user.userid`
* **Impact:** This condition simply checks if the actor ID is different from the target mailbox owner. While true for automated service principals, it is also standard behavior for **human employees accessing shared or departmental mailboxes** (e.g., an operator opening `info@company.com`). This design flaw generates massive noise on standard operational human traffic.

---

### ✅ Tuned YARA-L Solutions for O365 Rules

To fix these severe design flaws, you have two options depending on your operational needs:

**Option 1: Native SIEM Exclusions (Quick Fix)**
You do not necessarily have to disable the rules or write custom code. You can simply create an **Exclusion** directly within the Google SecOps SIEM UI. Just add an exclusion targeting the `ClientAppId` of **Outlook Mobile** (`27922004-5251-4030-b22d-91ecd9a37ea4`) and your authorized backup applications (e.g., Keepit). This immediately stops the false positive flood while keeping Google's curated rules active.

**Option 2: Deploy Custom Rules (Architectural Fix)**
If you want to completely fix the underlying grouping logic flaws (such as the `$application_id` mismatch), you must disable the Curated Detections and deploy Custom Rules. The fixes involve:
1. Explicitly whitelisting Outlook Mobile (`27922004-...`).
2. Whitelisting known authorized Enterprise Backup Apps (e.g., Keepit).
3. Fixing the `match` sections to properly aggregate by session.

##### Tuned Rule 1: Multiple User Agents
```yara
rule custom_ttp_o365_mailbox_access_by_service_principal_with_multiple_uas {
  meta:
    rule_name = "[CUSTOM] O365 Mailbox Access by Service Principal with Multiple User Agents"
    description = "Detects a Service Principal with a single O365 session ID accessing O365 mailboxes with multiple user agents. Tuned to fix grouping logic and exclude Outlook Mobile (Public Client) human traffic."
    severity = "Low"
    tactic = "TA0009"
    technique = "T1114.002"

  events:
    $e.metadata.log_type = "OFFICE_365"
    $e.metadata.product_event_type = "MailItemsAccessed" nocase
    $e.target.application = "Exchange"
    $e.security_result.detection_fields["RecordType"] = /^(2|50)$/
    
    // Extract actual Session ID and App ID
    $session_id = $e.network.session_id
    $application_id = $e.additional.fields["ClientAppId"]
    
    $e.principal.user.userid !=$e.target.user.userid
    
    ( 
      $e.network.http.user_agent = /AppId/ nocase or$e.additional.fields["ClientAppId"] = /./
    )
    
    // EXCLUSIONS: Added Outlook Mobile + Standard Google Exclusions
    $e.additional.fields["ClientAppId"] != /^(27922004-5251-4030-b22d-91ecd9a37ea4\vert{}bea75f7a-2505-46e8-9bf6-d3f7da9c9da7\vert{}b52893c8-bc2e-47fc-918b-77022b299bbc\vert{}...)$/ nocase

  match:
    // Group by both App AND Session to isolate the specific token lifecycle
    $application_id,$session_id over 3h

  outcome:
    $vendor_name = "Microsoft"
    $product_name = "Office 365"
    $source_ua_dc = count_distinct($e.network.http.user_agent)
    $client_app_id = array_distinct($e.additional.fields["ClientAppId"])

  condition:
    // Triggers if the SAME session rotates 2+ User Agents
    $e and $source_ua_dc >= 2
}

```

##### Tuned Rule 2: Multiple Mailboxes Accessed

*(Same logic, but in the exclusions ensure you whitelist your authorized backup solutions like Keepit (`a7cd46df...`) alongside Outlook Mobile).*

##### Tuned Rule 3: Multiple ASNs

*(Unlike the User Agents rule, Google actually managed to group by `$session_id` correctly in this one. However, it still lacks the Outlook Mobile exclusion. Follow the same exclusion logic as above, keeping the condition on `$source_asn_dc >= 2`).*

##### Tuned Rule 4: Multiple Mailboxes Accessed via Microsoft Graph API
*(Same logic. Ensure you append authorized backup applications like Keepit (`a7cd46df...`) to the exclusion regex at the end of the `events` block).*

---

## 2. UEBA: Anomalous Auth Attempts Total

**Rule:** `Anomalous Auth Attempts Total by Principal Hostname and Target User ID`

*(Note: UEBA stands for "User and Entity Behavior Analytics". These rules do not use static signatures, but instead rely on mathematical algorithms to baseline "normal" behavior and alert on statistical deviations).*

### ❌ Hardcoding Flaw & Alert Fatigue

This UEBA rule attempts to detect anomalous authentication spikes by calculating the historical average and standard deviations over 30 days.

* **Alert Fatigue:** In our production environment, this curated rule generated an incredibly low True Positive rate (~0.08%, with 2 actionable tickets out of 2324 alerts). It is essentially pure noise.
* **Code Flaw:** Google declares a variable `$num_stddevs_away = max(2)` at the beginning of the outcome block. However, in the `$historical_threshold` calculation, **the Google developer hardcoded the value `2` instead of using the variable**. This programming error prevents analysts from easily overriding the sensitivity via the UI or inherited variables without completely cloning and rewriting the YARA-L logic.

### ✅ UEBA Tuning Recommendations

Real-world testing shows that simply tweaking statistical thresholds (e.g., raising `$num_stddevs_away` to 3 or 4, lowering `$coefficient_of_variation_threshold` from `0.1` to `0.05`, or increasing `$observation_threshold` to 15) is insufficient: it drops counts from 710 to 111 weekly alerts, which remains excessively noisy for an analyst team.

* **Recommended Approach:** For SecOps enterprise tenants, **disable the `Broad` ruleset alerting** for "Failed Authentications by Device" and rely strictly on the `Precise` alerting channel. This structural mitigation is the only effective way to stop the alert flood.
* **Alternative Custom Approach:** If you must keep it active, clone the rule into a Custom Rule, fix the hardcoded `2` inside `$historical_threshold` to match your custom `$num_stddevs_away` variable, and enforce stricter baseline coefficients.

---

*Disclaimer: These tunings are based on real-world incident response and SIEM engineering experience. Always test YARA-L rules in your specific environment before deploying them to production.*
