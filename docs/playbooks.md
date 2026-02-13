# Incident Response Playbooks

Six playbooks covering the full ICS Cyber Kill Chain. Playbook #1 is fully automated via Wazuh active response. All others provide structured response procedures for SOC analysts.

## Playbook #1: Unauthorized Modbus Write — AUTOMATED

**Trigger:** Suricata alerts for Modbus write functions (SID 9000001-9000004) → Wazuh rule 100101

**Severity:** Level 7 (auto-escalates to 12 if flooding detected via rule 100103)

**MITRE ATT&CK:** T0883 (Change Operating Mode)

| Step | Action | Automated? |
|------|--------|-----------|
| Detect | Suricata matches Modbus FC 0x05/06/0F/10 at byte offset 7 | Yes |
| Correlate | Wazuh chains 86601 → 100100 → 100101 | Yes |
| **Contain** | **firewall-drop blocks source IP for 600 seconds** | **Yes** |
| Enrich | Identify source IP, destination PLC, function code used | Manual |
| Investigate | Review Zeek conn.log for full session timeline; check if source is known HMI | Manual |
| Recover | Validate PLC register/coil state; restore known-good values if tampered | Manual |

**Configuration:** `config/wazuh/ossec.conf` → `<active-response>` block

---

## Playbook #2: Modbus Reconnaissance

**Trigger:** Suricata alerts for Modbus read/diagnostics (SID 9000010-9000021) → Wazuh rules 100102, 100104

**Severity:** Level 5-6

**MITRE ATT&CK:** T0802 (Automated Collection), T0846 (Remote System Discovery)

| Step | Action |
|------|--------|
| Detect | Suricata matches Modbus FC 0x01/04 (reads) or FC 0x08/2B (diagnostics) |
| Correlate | Wazuh chains 86601 → 100100 → 100102 or 100104 |
| Enrich | Identify scanning host, target PLCs, time window, register ranges probed |
| Triage | Determine if source is authorized (SCADA polling station vs unknown host) |
| Contain | If unauthorized: block source IP; if authorized: update whitelist |
| Investigate | Check if recon is followed by write attempts (kill chain progression) |

**Tuning note:** In environments with SCADA polling, rule 100102 will fire frequently. Whitelist known polling stations or raise the alert level threshold.

---

## Playbook #3: Denial of Control (Modbus Flooding)

**Trigger:** 6+ Modbus write events in 30 seconds → Wazuh rule 100103

**Severity:** Level 12 (CRITICAL)

**MITRE ATT&CK:** T0813 (Denial of Control)

| Step | Action |
|------|--------|
| Detect | Wazuh frequency-based correlation: 100101 fires 6+ times in 30 seconds |
| Correlate | Rule 100103 escalates to level 12 |
| Contain | Source IP already blocked by Playbook #1 (100101 → firewall-drop) |
| Assess | Determine if PLC is still responsive; check if operator control is restored |
| Recover | If PLC is unresponsive: cycle power or reload program; verify all setpoints |
| Post-incident | Compare current register values against known-good baseline |

**Key distinction:** A single unauthorized write (Playbook #1) is concerning. A flood of writes (this playbook) indicates an active Denial of Control attack — the attacker is continuously overriding operator corrections.

---

## Playbook #4: SSH Brute Force Against OT Infrastructure

**Trigger:** 8+ SSH authentication failures in 120 seconds → Wazuh rules 5712 → 100110

**Severity:** Level 12 (CRITICAL)

**MITRE ATT&CK:** T0886 (Remote Services)

| Step | Action |
|------|--------|
| Detect | Wazuh sshd decoder extracts failed login events from auth.log |
| Correlate | Rule 5712 (frequency) → 100110 (OT escalation to level 12) |
| Enrich | Identify source IP, targeted usernames, timing pattern |
| Contain | Block source IP at network perimeter; disable targeted accounts if compromised |
| Investigate | Check if any login succeeded after the brute force; review auth.log for success events |
| Harden | Enforce SSH key-only authentication; disable password auth on OT systems |

**OT context:** SSH brute force against an OT system is more critical than against a typical IT server because successful access gives the attacker direct control over PLC programming environments.

---

## Playbook #5: Web Application Attacks Against HMI

**Trigger:** SQL injection or XSS patterns in web access logs → Wazuh rules 100120, 100121, 100122

**Severity:** Level 10-14

**MITRE ATT&CK:** T0866 (Exploitation of Remote Services)

| Step | Action |
|------|--------|
| Detect | Wazuh web-accesslog decoder matches SQLi patterns (31103/31104) or XSS patterns (31105) |
| Correlate | Custom rules 100120/100121 chain from built-in web rules with OT HMI URL filter |
| Triage | Check HTTP status code — 200 means the attack may have succeeded (rule 100122, level 14) |
| Contain | Block source IP; rotate HMI session tokens; reset admin credentials |
| Investigate | Review web server logs for data exfiltration; check if PLC programs were modified |
| Recover | Verify PLC program integrity; compare against known-good program backup |

**Level 14 (100122)** — If a web attack returns HTTP 200, the application processed the malicious input. In an OT context, this could mean the attacker bypassed HMI authentication and can now modify PLC programs.

---

## Playbook #6: Configuration Tampering (File Integrity)

**Trigger:** File checksum change on monitored system files → Wazuh rules 550, 554

**Severity:** Level 7

**MITRE ATT&CK:** T0831 (Manipulation of Control)

| Step | Action |
|------|--------|
| Detect | Wazuh syscheck detects file modification (checksum, permissions, or ownership change) |
| Correlate | Rules 550 (file modified) or 554 (file added) fire |
| Enrich | Identify which file changed, what changed (diff if available), timestamp |
| Triage | Determine if change was authorized (maintenance window, change ticket) |
| Contain | If unauthorized: restore from backup; investigate how attacker gained file-level access |
| Investigate | Check for persistence mechanisms: cron jobs, SSH keys, modified DNS/hosts |

**Common targets in OT:**
- `/etc/resolv.conf` — DNS hijacking for C2 communication
- `/etc/hosts` — Redirect update servers to attacker-controlled infrastructure
- PLC program files — Direct manipulation of control logic
- Firewall rules — Opening backdoor access to OT network
