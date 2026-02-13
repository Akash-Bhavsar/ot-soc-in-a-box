# Active Response (SOAR Automation)

This document describes the automated incident response capabilities built into the detection pipeline, the architectural decisions behind them, and the critical safety considerations for deploying automated response in OT environments.

## SOAR Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Detection Pipeline                        │
│                                                              │
│  Suricata ──► eve.json ──► Wazuh Logcollector               │
│                                  │                           │
│                           JSON Decoder                       │
│                                  │                           │
│                          Rule 86601 (Suricata alert)         │
│                                  │                           │
│                          Rule 100100 (OT telemetry)          │
│                                  │                           │
│                          Rule 100101 (Modbus write, lvl 7)   │
│                                  │                           │
│                    ┌─────────────┴────────────┐              │
│                    │                          │              │
│               Alert Logged            Active Response         │
│           (alerts.json +              Triggered              │
│            OpenSearch)                    │                   │
│                                          ▼                   │
│                                  firewall-drop               │
│                                  (iptables block)            │
│                                       │                      │
│                                  Source IP blocked            │
│                                  for 600 seconds             │
│                                       │                      │
│                                  Rule 651 logged             │
│                                  (block confirmed)           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

The active response is defined in `config/wazuh/ossec.conf`:

```xml
<!-- SOAR: Auto-block source IP on unauthorized Modbus write (Playbook #1) -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101</rules_id>
  <timeout>600</timeout>
</active-response>
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `command` | `firewall-drop` | Uses iptables to DROP packets from source IP |
| `location` | `local` | Executes on the Wazuh Manager (where the alert is processed) |
| `rules_id` | `100101` | Triggers only on Modbus write detections |
| `timeout` | `600` | Block automatically expires after 10 minutes |

The `firewall-drop` command is a built-in Wazuh active response script located at `/var/ossec/active-response/bin/firewall-drop`. It adds an iptables rule to block the source IP and automatically removes it after the timeout.

## Why Only Rule 100101?

Automated blocking is only enabled for Modbus write operations (rule 100101), not for all OT detections. This is a deliberate architectural decision:

| Rule | Auto-Block? | Rationale |
|------|-------------|-----------|
| 100101 (Modbus write) | **Yes** | Unauthorized writes can cause immediate physical harm. The risk of allowing continued writes far exceeds the risk of a false positive block. |
| 100102 (Modbus read) | No | Reads are passive — they don't change process state. Blocking a legitimate polling station would cause loss of visibility. |
| 100103 (flooding) | No | By the time flooding is detected (6+ writes), the source IP is already blocked by 100101's response. |
| 100110 (SSH brute force) | No | SSH brute force detection depends on accumulated failures. Blocking too early might block a legitimate admin who mistyped a password. |
| 100120/121 (web attacks) | No | Web attacks against the HMI don't directly affect the physical process. Manual investigation is preferred. |

## OT Safety Considerations

Automated response in OT environments requires careful consideration of safety implications. Unlike IT environments where blocking a host causes a service disruption, blocking in OT can cause **physical safety incidents**.

### Risks of Automated Blocking in OT

1. **False positive blocks on legitimate control traffic**
   - If a legitimate HMI or engineering workstation triggers a Modbus write detection, the automated block would sever its connection to the PLC
   - The PLC continues running its last program, but operators lose the ability to make adjustments or respond to process changes
   - Mitigation: Whitelist known HMI/EWS source IPs in the rule

2. **Blocking during an active safety event**
   - If an operator needs to send emergency shutdown commands and the firewall-drop blocks their traffic, the safety response is delayed
   - Mitigation: The 10-minute timeout ensures blocks are temporary; configure safety systems on a separate network segment not subject to the same rules

3. **Cascading failures**
   - In environments with redundant control paths, blocking one controller might cause traffic to failover to another, which then gets flagged and blocked
   - Mitigation: Use IP whitelists for known control system addresses

### Production Recommendations

For deploying this SOAR pattern in production OT environments:

1. **Start in alert-only mode** — Remove the `<active-response>` block and monitor alerts for 30-60 days to establish a baseline
2. **Build a whitelist** — Identify all legitimate Modbus write sources (HMI stations, engineering workstations, SCADA servers) and exclude them from automated response
3. **Use tiered response** — Instead of a single block action, implement escalating responses:

```
Tier 1: Alert only (Level 5-6)
   └── Modbus reads, device fingerprinting
       → Log and enrich, no action

Tier 2: Alert + ticket (Level 7-10)
   └── Single Modbus write, SSH failures
       → Create incident ticket, notify SOC analyst

Tier 3: Alert + isolate (Level 12+)
   └── Flooding, brute force, confirmed web attack
       → Automated block + SOC notification + incident creation

Tier 4: Alert + emergency (Level 14+)
   └── Successful web attack, multiple attack phases
       → Block + page on-call + OT operator notification
```

4. **Never block safety systems** — Safety Instrumented Systems (SIS) should be on isolated networks that are never subject to automated response rules
5. **Test response actions** — Use the attack simulation script in a maintenance window to verify the response chain works correctly before enabling in production

## Monitoring Active Response

### Viewing Block History

```bash
# Check active response log
docker exec ot-wazuh-manager cat /var/ossec/logs/active-responses.log

# Check current iptables blocks
docker exec ot-wazuh-manager iptables -L INPUT -n | grep DROP

# Count total blocks in alerts
docker exec ot-wazuh-manager grep -c '"id":"651"' /var/ossec/logs/alerts/alerts.json
```

### Manually Removing a Block

If you need to unblock a source IP before the 600-second timeout:

```bash
docker exec ot-wazuh-manager iptables -D INPUT -s <blocked-ip> -j DROP
```

## Integration Points

The SOAR automation integrates with:

| Component | Integration |
|-----------|-------------|
| **Suricata** | Source of Modbus write alerts (eve.json) |
| **Wazuh Manager** | Processes rules and triggers active response |
| **iptables** | Enforcement point for IP blocks |
| **OpenSearch** | Stores alert + response history for post-incident analysis |
| **Wazuh Dashboard** | Visualizes both alerts and response actions |
