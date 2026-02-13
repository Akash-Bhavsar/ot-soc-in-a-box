# Detection Engineering

This document details the detection architecture — how raw OT telemetry flows through decoders, matches rule chains, and produces actionable security alerts. Understanding these chains is essential for tuning detections and reducing false positives in production OT environments.

## Telemetry Pipeline

```
OT Zone Traffic (Modbus/TCP)
    │
    ├── Suricata IDS ──► eve.json ──► Wazuh logcollector (JSON format)
    │                                      │
    │                                      ├── Built-in JSON decoder
    │                                      ├── Rule 86600 (Suricata event)
    │                                      ├── Rule 86601 (Suricata alert)
    │                                      └── Custom rules 100100-100104
    │
    ├── Zeek NSM ──► conn.log ──► Wazuh logcollector (JSON format)
    │                                  │
    │                                  ├── Built-in JSON decoder
    │                                  └── Custom rule 100200
    │
    ├── SSH auth ──► auth.log ──► Wazuh logcollector (syslog format)
    │                                 │
    │                                 ├── sshd decoder
    │                                 ├── Rules 5710 → 5712 (brute force)
    │                                 └── Custom rules 100110-100111
    │
    └── Web access ──► openplc-access.log ──► Wazuh logcollector (apache format)
                                                  │
                                                  ├── web-accesslog decoder
                                                  ├── Rules 31100 → 31103-31106
                                                  └── Custom rules 100120-100122
```

## Decoder Chain Analysis

### Chain 1: Suricata → OT Modbus Detection

**Path:** `eve.json → JSON decoder → 86600 → 86601 → 100100 → 100101/100102/100104`

```
Step 1: Logcollector reads eve.json (log_format: json)
Step 2: Built-in JSON decoder extracts all fields
Step 3: Rule 86600 matches event_type: "alert" (Suricata base event)
Step 4: Rule 86601 matches with Suricata alert details (level 3)
Step 5: Rule 100100 chains from 86601 with location filter:
        <if_sid>86601</if_sid>
        <location>/var/ot/telemetry/suricata/eve.json</location>
Step 6: Rules 100101/100102/100104 match on alert.signature_id:
        100101: ^900000\d$  → SID 9000001-9000004 (writes)
        100102: ^900001\d$  → SID 9000010-9000011 (reads)
        100104: ^900002\d$  → SID 9000020-9000021 (diagnostics)
```

**Key insight:** Rule 100100 uses `<location>` to ensure only OT telemetry events (not generic Suricata alerts) enter the OT rule chain. This prevents non-OT Suricata deployments from triggering ICS rules.

**Example decoded event:**
```json
{
  "timestamp": "2026-02-13T12:00:00.000000+0000",
  "event_type": "alert",
  "src_ip": "10.0.100.50",
  "dest_ip": "172.18.0.3",
  "dest_port": 502,
  "alert": {
    "signature_id": 9000001,
    "signature": "ICS Modbus Write Single Coil",
    "severity": 1
  }
}
```

### Chain 2: SSH Brute Force Detection

**Path:** `auth.log → sshd decoder → 5710 → 5712 → 100110`

```
Step 1: Logcollector reads auth.log (log_format: syslog)
Step 2: sshd decoder extracts: srcip, srcuser, program_name
Step 3: Rule 5710 fires: "Attempt to login using a non-existent user" (level 5)
Step 4: Rule 5712 fires: frequency-based, 8+ failures in 120 seconds (level 10)
Step 5: Rule 100110 chains from 5712, escalates to level 12 for OT context
```

**Why escalate?** Built-in rule 5712 is level 10 — appropriate for generic SSH brute force. In an OT environment, SSH access to a SCADA system is a critical initial access vector (MITRE T0886), warranting a higher severity.

### Chain 3: Web Attack Detection (SQLi/XSS)

**Path:** `web access log → web-accesslog decoder → 31100 → 31103/31104/31105 → 100120/100121/100122`

```
Step 1: Logcollector reads openplc-access.log (log_format: apache)
Step 2: web-accesslog decoder extracts: srcip, url, id (HTTP status)
Step 3: Rule 31100 groups all web access events (level 0)
Step 4: Content rules match malicious URL patterns:
        31103: SQL injection (select+, union+, where+, xp_cmdshell)
        31104: Injection/traversal (%027, %00, %2E%2E, ../..)
        31105: XSS (%3Cscript, script>, SRC=javascript, iframe)
Step 5: Rule 31106 matches if status code is 200 (attack succeeded)
Step 6: Custom rules chain from these:
        100120: SQLi against OT HMI (chains from 31104, level 12)
        100121: XSS against OT HMI (chains from 31105, level 10)
        100122: Successful web attack (chains from 31106, level 14)
```

**URL filter in rule 100120:**
```xml
<url>openplc|login|hardware|programs|dashboard|monitoring</url>
```
This narrows SQL injection detections to OT HMI-specific endpoints, reducing false positives from generic web scanning.

### Chain 4: Modbus Flooding (Frequency-Based)

**Path:** `100101 fires 6+ times in 30 seconds → 100103`

```xml
<rule id="100103" level="12" frequency="5" timeframe="30">
  <if_matched_sid>100101</if_matched_sid>
  <description>CRITICAL: OT Modbus write flooding - Denial of Control</description>
</rule>
```

**How it works:** This uses Wazuh's frequency-based correlation. When rule 100101 (Modbus write) fires 6 or more times within a 30-second window, rule 100103 triggers at level 12 — indicating a Denial of Control attack rather than isolated write operations.

**Why `frequency="5"` means 6 events:** Wazuh's frequency counter starts at 0. A frequency of 5 means "after the initial event, if 5 more occur within the timeframe" = 6 total events.

## Suricata Rule Design

All 8 Suricata rules use the same pattern for Modbus/TCP detection:

```
alert tcp any any -> any any (
  msg:"ICS Modbus Write Single Coil";
  flow:to_server,established;
  content:"|05|";
  offset:7;
  depth:1;
  sid:9000001;
  rev:2;
)
```

**Why offset:7, depth:1?**

Modbus/TCP frame structure:
```
Bytes 0-1:  Transaction ID
Bytes 2-3:  Protocol ID (0x0000 for Modbus)
Bytes 4-5:  Length
Byte  6:    Unit ID
Byte  7:    Function Code  ← This is what we match
```

The function code at byte offset 7 identifies the operation. By matching a single byte at offset 7 with depth 1, we precisely target the Modbus function code without false positives from payload data.

**Why `any any -> any any`?**

In a lab environment, we match all traffic. In production, you would restrict this to known OT network ranges:
```
alert tcp $EXTERNAL_NET any -> $OT_NETWORK 502 (...)
```

## False Positive Analysis

| Rule | Potential False Positives | Mitigation |
|------|-------------------------|------------|
| 100101 (Modbus write) | Legitimate PLC programming or HMI commands | Whitelist known HMI source IPs; use time-based rules (writes outside maintenance windows) |
| 100102 (Modbus read) | Normal SCADA polling cycles | In production, tune frequency threshold or exclude known polling stations |
| 100103 (flooding) | Rapid legitimate control loops | Increase frequency threshold; whitelist control system IPs |
| 100110 (SSH brute force) | Failed password from legitimate admin | Wazuh 5712 requires 8+ failures — single failures don't trigger |
| 100120 (SQLi) | URL parameters containing SQL keywords | Rule 100120 filters by OT HMI URL paths to reduce noise |

## Tuning Guide

### Adjusting Alert Levels

To change the severity of a rule without modifying the original file, create an override in `config/wazuh/rules/ot-soc_rules.xml`:

```xml
<!-- Lower Modbus read alerts from level 5 to level 3 in environments with heavy polling -->
<rule id="100102" level="3" overwrite="yes">
  <if_sid>100100</if_sid>
  <field name="alert.signature_id">^900001\d$</field>
  <description>OT Modbus read operation (tuned - polling environment)</description>
</rule>
```

### Adding IP Whitelists

To exclude known legitimate sources from triggering OT rules:

```xml
<rule id="100101" level="7">
  <if_sid>100100</if_sid>
  <field name="alert.signature_id">^900000\d$</field>
  <field name="data.src_ip" negate="yes">^192\.168\.1\.(10|20|30)$</field>
  <description>OT Modbus write from unauthorized source</description>
</rule>
```

### Adjusting Flood Thresholds

For environments with higher legitimate write rates, increase the frequency threshold:

```xml
<rule id="100103" level="12" frequency="15" timeframe="60">
  <if_matched_sid>100101</if_matched_sid>
  <description>CRITICAL: OT Modbus write flooding (tuned threshold)</description>
</rule>
```

## Detection Gaps

These attacks are NOT currently detected by this lab and represent areas for future work:

| Gap | Why | Possible Solution |
|-----|-----|-------------------|
| Modbus function code 0x03 (Read Holding Registers) | No Suricata rule for FC 0x03 | Add SID 9000012 matching content `\|03\|` at offset 7 |
| Modbus exception responses | Only client→server traffic monitored | Add rules for server→client with exception codes |
| Encrypted Modbus (TLS) | Suricata can't inspect encrypted payloads | Deploy TLS termination proxy or use Zeek's SSL metadata |
| Slow-and-low attacks | Frequency rules only catch bursts | Lower thresholds with longer timeframes |
| Legitimate credential reuse | SSH rules can't distinguish valid vs stolen creds | Integrate with asset inventory for behavioral baseline |
| Lateral movement post-compromise | No east-west traffic monitoring between OT devices | Add Zeek/Suricata on internal OT segments |
