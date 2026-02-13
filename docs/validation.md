# Validation

Procedures for verifying the lab is healthy and all detection capabilities are functioning correctly.

## 1. Launch the Lab

```bash
./scripts/start.sh
```

The start script:
- Checks Docker and Docker Compose are installed
- Pulls container images
- Starts all 8 services
- Waits for healthchecks (up to 120 seconds)
- Runs preflight checks
- Prints access URLs and credentials

## 2. Preflight Checks

```bash
./scripts/preflight.sh
```

Validates:
- All containers are running and healthy
- Telemetry paths exist (`/var/ot/telemetry/suricata/`, `/var/ot/telemetry/zeek/`)
- Wazuh logcollector is monitoring `eve.json` and `conn.log`
- `wazuh-analysisd` is running
- Custom rules and decoders are mounted
- Wazuh Agent is registered with the Manager

Expected output: `Preflight completed successfully.`

## 3. Quick Smoke Test

```bash
./scripts/test_lab.sh
```

Runs a 5-step verification:
1. Container health check (all 8 running)
2. Send real Modbus write from OpenPLC to Modbus Simulator
3. Inject synthetic Suricata alert into eve.json
4. Verify Wazuh rule 100101 fires
5. Check Zeek conn.log has entries

## 4. Full Attack Simulation

```bash
./scripts/attack_sim.sh
```

Runs the complete 7-phase ICS Cyber Kill Chain:

| Phase | What to Verify |
|-------|---------------|
| 1. Reconnaissance | Rules 100102, 100104 fire (check Phase 7 output) |
| 2. SSH Brute Force | Rule 100110 fires |
| 3. Web Exploitation | Rules 100120, 100121 fire |
| 4. OT Manipulation | Rule 100101 fires + active response (rule 651) |
| 5. Persistence | FIM rules 550/554 fire (may take up to 12 hours for syscheck cycle) |
| 6. Flooding | Rule 100103 fires (level 12) |
| 7. Verification | Automated summary of all rule hits |

The script prints a verification table at the end showing hit counts for each rule.

## 5. Import Dashboard

```bash
./scripts/create_dashboard.sh
```

Imports the pre-built OT SOC dashboard into Wazuh Dashboard. After import:

1. Open http://localhost:15601
2. Login: `admin` / `SecureAdmin123!`
3. Navigate to **OpenSearch Dashboards** > **Dashboard**
4. Select the OT SOC dashboard

## 6. Manual Verification

### Check Wazuh Alerts

```bash
# View recent alerts
docker exec ot-wazuh-manager tail -5 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool

# Count alerts by rule ID
docker exec ot-wazuh-manager bash -c "cat /var/ossec/logs/alerts/alerts.json | \
  python3 -c \"import sys,json; \
  rules={}; \
  [rules.update({(a:=json.loads(l)).get('rule',{}).get('id','?'): \
    rules.get(a.get('rule',{}).get('id','?'),0)+1}) for l in sys.stdin if l.strip()]; \
  [print(f'  Rule {k}: {v} hits') for k,v in sorted(rules.items())]\""
```

### Check Active Response

```bash
# View firewall blocks
docker exec ot-wazuh-manager cat /var/ossec/logs/active-responses.log

# View current iptables rules
docker exec ot-wazuh-manager iptables -L INPUT -n | grep DROP
```

### Check Suricata Alerts

```bash
# Count alerts by signature
docker exec ot-suricata bash -c "cat /var/ot/telemetry/suricata/eve.json | \
  python3 -c \"import sys,json; \
  sigs={}; \
  [sigs.update({(a:=json.loads(l)).get('alert',{}).get('signature','?'): \
    sigs.get(a.get('alert',{}).get('signature','?'),0)+1}) \
    for l in sys.stdin if l.strip() and 'alert' in l]; \
  [print(f'  {v:4d}x {k}') for k,v in sorted(sigs.items())]\""
```

### Check Zeek Connections

```bash
docker exec ot-wazuh-manager wc -l /var/ot/telemetry/zeek/conn.log
```

## Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| Wazuh Dashboard | http://localhost:15601 | admin / SecureAdmin123! |
| Wazuh API | https://localhost:15500 | admin / SecurePassword123! |
| OpenSearch | https://localhost:19200 | admin / SecureAdmin123! |
| OpenPLC Web | http://localhost:8080 | openplc / openplc |
| Modbus Simulator | localhost:1502 (TCP) | — |
