# Detections

Complete reference of all detection rules deployed in the lab.

## Telemetry Sources

| Source | Format | Location | What It Captures |
|--------|--------|----------|-----------------|
| Suricata IDS | JSON | `/var/ot/telemetry/suricata/eve.json` | Protocol-level IDS alerts (Modbus function codes) |
| Zeek NSM | JSON | `/var/ot/telemetry/zeek/conn.log` | Connection metadata (IPs, ports, duration, bytes) |
| SSH auth | syslog | `/var/log/auth.log` | SSH login attempts (success/failure) |
| Web access | Apache | `/var/log/openplc-access.log` | HTTP requests to OpenPLC HMI |
| Active response | syslog | `/var/ossec/logs/active-responses.log` | Automated containment actions |

## Suricata IDS Rules (8 rules)

File: `config/suricata/rules/ics-local.rules`

### Write Operations (Exploitation)

| SID | Message | Content Match | MITRE |
|-----|---------|--------------|-------|
| 9000001 | ICS Modbus Write Single Coil | `\|05\|` at offset 7 | T0883 |
| 9000002 | ICS Modbus Write Single Register | `\|06\|` at offset 7 | T0883 |
| 9000003 | ICS Modbus Write Multiple Coils | `\|0F\|` at offset 7 | T0883 |
| 9000004 | ICS Modbus Write Multiple Registers | `\|10\|` at offset 7 | T0883 |

### Read Operations (Reconnaissance)

| SID | Message | Content Match | MITRE |
|-----|---------|--------------|-------|
| 9000010 | ICS Modbus Read Coils | `\|01\|` at offset 7 | T0802 |
| 9000011 | ICS Modbus Read Input Registers | `\|04\|` at offset 7 | T0802 |

### Diagnostics (Fingerprinting)

| SID | Message | Content Match | MITRE |
|-----|---------|--------------|-------|
| 9000020 | ICS Modbus Diagnostics Request | `\|08\|` at offset 7 | T0846 |
| 9000021 | ICS Modbus Device Identification | `\|2B\|` at offset 7 | T0846 |

## Wazuh Correlation Rules (13 rules)

File: `config/wazuh/rules/ot-soc_rules.xml`

### OT/Suricata Rules

| Rule ID | Level | Chains From | Description | MITRE |
|---------|-------|-------------|-------------|-------|
| 100100 | 3 | 86601 | Base: any Suricata alert from OT telemetry pipeline | — |
| 100101 | 7 | 100100 | Modbus write operation detected (SID 9000001-9000004) | T0883 |
| 100102 | 5 | 100100 | Modbus register enumeration (SID 9000010-9000011) | T0802 |
| 100103 | 12 | 100101 (freq) | Modbus write flooding — Denial of Control (6+ in 30s) | T0813 |
| 100104 | 6 | 100100 | Device fingerprinting (SID 9000020-9000021) | T0846 |

### SSH Brute Force Rules

| Rule ID | Level | Chains From | Description | MITRE |
|---------|-------|-------------|-------------|-------|
| 100110 | 12 | 5712 | SSH brute force targeting OT infrastructure | T0886 |
| 100111 | 10 | 5720 | Repeated SSH authentication failures on OT system | T0886 |

### Web Attack Rules

| Rule ID | Level | Chains From | Description | MITRE |
|---------|-------|-------------|-------------|-------|
| 100120 | 12 | 31104 | SQL injection against OT HMI web interface | T0866 |
| 100121 | 10 | 31105 | XSS against OT HMI/SCADA web interface | T0866 |
| 100122 | 14 | 31106 | Web attack returned success (HTTP 200) | T0866 |

### Zeek Metadata Rule

| Rule ID | Level | Chains From | Description | MITRE |
|---------|-------|-------------|-------------|-------|
| 100200 | 3 | json decoder | Modbus TCP connection observed on port 502/5020 | — |

## Built-In Rules Leveraged

The custom rules chain from these Wazuh built-in rules:

| Rule ID | Level | Description | Used By |
|---------|-------|-------------|---------|
| 86600 | 0 | Suricata event (base) | — |
| 86601 | 3 | Suricata alert | 100100 |
| 5710 | 5 | SSH login with non-existent user | 5712 |
| 5712 | 10 | SSH brute force (8+ failures/120s) | 100110 |
| 5720 | 10 | Multiple SSH auth failures | 100111 |
| 31100 | 0 | Web access log event (base) | 31103-31106 |
| 31103 | 7 | SQL injection (select/union patterns) | 100120 |
| 31104 | 6 | SQL injection/traversal (%027, %2E%2E) | 100120 |
| 31105 | 6 | XSS (%3Cscript, SRC=javascript) | 100121 |
| 31106 | 12 | Web attack with 200 response | 100122 |
| 550 | 7 | File integrity: file modified | — |
| 554 | 7 | File integrity: file added | — |
| 651 | 3 | Active response: host blocked | — |

## Active Response

| Trigger Rule | Action | Target | Timeout |
|-------------|--------|--------|---------|
| 100101 | `firewall-drop` | Source IP (iptables DROP) | 600 seconds |

See [active-response.md](active-response.md) for SOAR architecture details.
