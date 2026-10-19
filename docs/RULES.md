# Correlation rules and limitations

These four original heuristics illustrate evidence-based defensive triage. Severity is a fixed review priority, not a threat score or likelihood estimate. There is no trained classifier or production evaluation corpus.

## R01 — Failure burst followed by successful authentication

At least three distinct failures for the same tenant, actor and source IP strictly precede a success, all within 300 seconds of it. A previous success for that key resets earlier failures. The success and all qualifying failures are cited.

Legitimate password mistakes and approved testing can match. Distributed attempts, slow guessing, missing failures and attempts with no success are missed. R01 is conceptually informed by [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/), whose detection guidance includes correlating failure bursts with subsequent success. A match is not proof of brute force or valid-account compromise.

## R02 — Privileged elevation after authentication

The latest strictly earlier successful authentication within 600 seconds must match tenant, actor, session and source IP. A role change must take the subject from viewer/member to admin/owner. Custom role hierarchies and admin-to-owner transitions are outside scope. Both the authentication and role-change event are cited.

Approved onboarding or access changes can match. Session omission, source-IP changes and incomplete role logs lead to missed matches. The role-change subject must be the same identity as the authenticated actor; this is not a granting-administrator activity rule. [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/) provides context for credential abuse and privileged access, not a claim that this specific correlation proves compromise.

## R03 — Token source transition

A token use explicitly marked `expected_source=false` follows the latest `expected_source=true` use of that token reference, for the same tenant and actor, from a different source IP within 600 seconds. Both uses are cited.

Failover, NAT, dynamic infrastructure and incorrect policy labels can match. With no trusted expected-source annotation there is no valid baseline. Reused token identifiers, changing ownership and use outside the time window can defeat the rule. It neither parses tokens nor proves theft. Its T1078 mapping is contextual: a token can represent an authenticated principal, but the event pattern alone does not establish the technique.

## R04 — Restricted data returned outside policy

A successful authentication is followed within 600 seconds by a data-access event for the same tenant, actor, session and source IP, with `classification=restricted`, `authorized=false`, and `records>0`. The latest matching authentication and access event are cited.

Incorrect policy/classification labels, approved exceptions or incorrectly counted records can match. Zero-record denials, missing sessions, unknown policy decisions and unclassified resources are deliberately excluded. It detects an explicit annotated policy inconsistency; it does not infer exfiltration or data sensitivity. No ATT&CK technique is asserted for this rule.

## Case boundaries

Findings are processed deterministically by trigger time and finding ID. They may join an existing case with the same tenant and actor only if the combined earliest evidence to latest trigger spans at most 900 seconds. Adding earlier evidence can move the anchor backward; it never slides forward. A later finding that would exceed the full span starts a separate case. Within the same case, rule-specific session/IP constraints still apply.

A case has high priority if any finding is high priority. Otherwise it is medium. Case IDs are derived from sorted finding IDs; finding IDs come from the rule ID and ordered evidence references. Identity or rule-input changes therefore change the associated identifiers. IDs are correlation references, not external incident-management tickets.
