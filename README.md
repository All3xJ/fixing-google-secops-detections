# Google SecOps (Chronicle) Curated Detections: Flaw Analysis & Tuning

This repository documents **architectural design flaws, logic discrepancies, and tuning strategies** for native **Google SecOps (Chronicle) Curated Detections**.

While Google Threat Intelligence (GTIG) provides exceptional conceptual threat coverage (such as tracking APT29/BRICKSTORM campaigns), raw YARA-L implementations of curated rules sometimes suffer from implementation oversights, such as grouping logic contradictions and hardcoded threshold variables. In real-world enterprise environments, this frequently leads to massive alert fatigue.

This project analyzes *why* native rules break or flood the SOC, and shares optimized Custom Rules and patches to resolve these issues.

---

## 📑 Table of Contents

1. [O365 Suite Alerting Failure for BRICKSTORM / APT29](#1-o365-suite-alerting-failure-for-brickstorm--apt29)
   - [Flaw 1: Grouping Logic Contradiction](#flaw-1-grouping-logic-contradiction)
   - [Flaw 2: Outlook Mobile Public Client Oversight](#flaw-2-outlook-mobile-public-client-oversight)
   - [Flaw 3: Shared Mailbox Collision](#flaw-3-shared-mailbox-collision)
   - [Tuned YARA-L Solutions](#tuned-yara-l-solutions-for-o365-rules)
2. [O365 Teams: External Impersonation Attempt](#2-o365-teams-external-impersonation-attempt)
   - [Flaw 1: Adversary vs. Target Inversion](#flaw-1-adversary-vs-target-inversion)
   - [Flaw 2: Erroneous Match Grouping Key](#flaw-2-erroneous-match-grouping-key)
   - [Tuned YARA-L Solution](#tuned-yara-l-solution-for-teams-impersonation)
3. [UEBA: Anomalous Auth Attempts Total](#3-ueba-anomalous-auth-attempts-total)
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

Despite the rule description explicitly stating: *"Detects a Service Principal with a single O365 session ID..."*, the YARA-L `match` section of the "Multiple User Agents" rule groups by `$application_id` instead of the session ID (`$session_id`). This completely contradicts the rule's stated objective.

* **Impact:** Unrelated employee sessions sharing the same enterprise App ID and same shared mail are merged across the entire tenant over a 3-hour window. This triggers false positives whenever any two distinct users authenticate via different user agents (e.g., iPhone vs. Android) under the same application, failing to isolate individual token hijacking.

#### Flaw 2: Outlook Mobile Public Client Oversight

The rules track anomalous behavioral patterns (changing IPs, ASNs, or User-Agents) tied to a specific `ClientAppId`. While Google includes an exclusion regex for several native Microsoft applications, they inexplicably omitted the most ubiquitous human mobile client: the **Microsoft Outlook Mobile App** (`27922004-5251-4030-b22d-91ecd9a37ea4`).

* **Impact:** Without filtering out this Public Client, legitimate employees reading shared mailboxes from their smartphones who move between networks (e.g., switching from Wi-Fi to 4G) inherently trigger the `Multiple ASNs` alerts. Different employees using iOS and Android to check the same departmental mailbox trigger the `Multiple User Agents` alert.

#### Flaw 3: Shared Mailbox Collision

To identify backend service accounts, Google's logic relies on this condition:
`$e.principal.user.userid != $e.target.user.userid`

* **Impact:** This condition simply checks if the actor ID is different from the target mailbox owner. While true for automated service principals, it is also standard behavior for **human employees accessing shared or departmental mailboxes** (e.g., an operator opening `info@company.com`). This design flaw generates massive noise on standard operational human traffic.

---

### ✅ Tuned YARA-L Solutions for O365 Rules

To fix these design flaws, you have two options depending on your operational needs:

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
    $session_id =$e.network.session_id
    $application_id =$e.additional.fields["ClientAppId"]

    $e.principal.user.userid !=$e.target.user.userid

    ( 
      $e.network.http.user_agent = /AppId/ nocase or$e.additional.fields["ClientAppId"] = /./
    )

    // EXCLUSIONS: Added Outlook Mobile + Standard Google Exclusions
    $e.additional.fields["ClientAppId"] != /^(27922004-5251-4030-b22d-91ecd9a37ea4|bea75f7a-2505-46e8-9bf6-d3f7da9c9da7|b52893c8-bc2e-47fc-918b-77022b299bbc|...)$/ nocase

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

## 2. O365 Teams: External Impersonation Attempt

**Rule:** `ttp_o365_teams_external_impersonation_attempt`

**Target Event:** `OFFICE_365` (`metadata.product_event_type = "TeamsImpersonationDetected"`)

Microsoft Defender for Office 365 inspects external inbound Microsoft Teams chats and flags potential domain or brand impersonation via the `TeamsImpersonationDetected` audit operation. When converted into YARA-L detection rules, the native curated implementation suffers from entity misattribution and match-key oversights.

### ❌ Core Flaws in the Detection Logic

```yara
// Native Flawed Implementation Sample
events:
  $e.metadata.log_type = "OFFICE_365"
  $e.metadata.product_event_type = /TeamsImpersonationDetected/ nocase
  $principal_userid =$e.principal.user.userid

match:
  $principal_userid over 1h

outcome:
  $result = "succeeded"
  $adversary_name = array_distinct($e.principal.user.userid)

```

#### Flaw 1: Adversary vs. Target Inversion

Chronicle's default parser maps the recipient `UserId` (the internal user who received the message) into `principal.user.userid`. The external actor attempting the impersonation resides inside the nested `Sender` object (`Sender.UPN`), parsed into `additional.fields["Sender_UPN"]`.

* **Impact:** By assigning `$adversary_name = array_distinct($e.principal.user.userid)`, the rule labels the **internal victim as the adversary** in downstream SOC alerts and SOAR cases.

#### Flaw 2: Erroneous Match Grouping Key

The rule enforces `match: $principal_userid over 1h`, grouping alerts by the recipient employee.

* **Impact:** If an attacker conducts an external phishing campaign targeting 30 internal employees simultaneously, SecOps generates **30 isolated alerts** instead of a single consolidated threat campaign. Conversely, if multiple distinct external actors reach out to the same internal user within 1 hour, their identities are merged into a single alert, obscuring multi-vector attempts.

---

### ✅ Tuned YARA-L Solution for Teams Impersonation

**Option 1: Alert Profile Adjustment (Quick Fix)**

A straightforward operational fix is to **disable alerting on the `Broad` ruleset** for this curated detection and keep strictly the **`Precise`** channel enabled. This prevents benign cross-tenant or unconfirmed impersonation events from flooding the analyst queue without requiring custom rule deployments.

**Option 2: Deploy Custom Rule (Architectural Fix)**

This custom rule keeps the original schema intact, modifying only the sender extraction, the match grouping key, and the adversary outcome field:

```yara
rule custom_ttp_o365_teams_external_impersonation_attempt {
  meta:
    rule_name = "[CUSTOM] O365 Teams External Impersonation Attempt"
    description = "This event is logged whenever Office 365 Teams an external message sender is detected to have potential impersonation activity. Tuned to group and attribute alerts by the external sender."
    severity = "Medium"
    tactic = "TA0001"
    technique = "T1566"

  events:
    $e.metadata.log_type = "OFFICE_365"
    $e.metadata.product_event_type = /TeamsImpersonationDetected/ nocase
    $sender_upn =$e.additional.fields["Sender_UPN"]

  match:
    $sender_upn over 1h

  outcome:
    $vendor_name = "Microsoft"
    $product_name = "Office 365"
    $result = "succeeded"
    $event_count = count_distinct($e.metadata.id)$risk_score = 50
    $adversary_name = array_distinct($sender_upn)
    $result_time = min($e.metadata.event_timestamp.seconds)

  condition:
    $e
}

```

---

## 3. UEBA: Anomalous Auth Attempts Total

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

```
