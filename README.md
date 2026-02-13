# OT SOC-in-a-Box

A production-grade OT/ICS security monitoring lab with detection engineering, automated SOAR response, and a full ICS Cyber Kill Chain attack simulation.

One command deploys an 8-service security operations center for industrial control systems — from PLC simulators to SIEM correlation to automated containment. Custom detection rules are mapped to [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/), with a 7-phase attack simulation that exercises the entire detection pipeline end-to-end.

## Architecture

```
┌────────────────────── OT Zone (Purdue Level 1/2) ───────────────────────┐
│                                                                          │
│   OpenPLC (PLC sim)  ◄──── Modbus/TCP ────►  Modbus Simulator           │
│   :8080 (HMI web)                              :5020 (Modbus server)    │
│                                                                          │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ mirrored traffic (passive tap)
┌────────────────────── OT DMZ (Level 3.5) ───────────────────────────────┐
│                                                                          │
│   Zeek (NSM)                              Suricata (IDS)                 │
│   ├─ conn.log (JSON)                      ├─ eve.json (alerts)           │
│   └─ protocol metadata                    └─ 8 custom ICS rules         │
│                                                                          │
│              └──────── /var/ot/telemetry/ (shared volume) ───────┘       │
│                                                                          │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ log ingestion
┌────────────────────── IT Zone (Level 4/5) ──────────────────────────────┐
│                                                                          │
│   Wazuh Manager (SIEM + SOAR)                                            │
│   ├─ 13 custom correlation rules (ot-soc_rules.xml)                     │
│   ├─ Decoder chains: JSON → Suricata/Zeek → OT correlation              │
│   ├─ Active Response: auto-block on unauthorized Modbus writes           │
│   └─ Ingests: Suricata, Zeek, auth.log, web access logs                 │
│                                                                          │
│   Wazuh Agent (host monitoring)                                          │
│   ├─ File integrity monitoring (FIM)                                     │
│   ├─ Rootkit detection                                                   │
│   └─ System inventory (syscollector)                                     │
│                                                                          │
│   OpenSearch ──► Wazuh Dashboard                                         │
│   :19200          :15601                                                 │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone and configure
git clone https://github.com/<your-username>/ot-soc-in-a-box.git
cd ot-soc-in-a-box
cp .env.example .env        # Edit .env to set your own passwords

# Start everything
./scripts/start.sh

# Import the OT SOC dashboard
./scripts/create_dashboard.sh

# Run the 7-phase attack simulation
./scripts/attack_sim.sh
```

Open the Wazuh Dashboard at **http://localhost:15601** and log in with the credentials from your `.env` file. Navigate to **Security Events** to see the alerts.

## Components

| Service | Image | Purpose | Zone | Port |
|---------|-------|---------|------|------|
| OpenPLC | `fdamador/openplc` | PLC simulator with Modbus/TCP + HMI web UI | OT | 8080, 502 |
| Modbus Simulator | `oitc/modbus-server` | OT traffic generator (Modbus server) | OT | 1502 |
| Zeek | `zeek/zeek` | Protocol-aware network metadata | DMZ | — |
| Suricata | `jasonish/suricata` | IDS with custom ICS/Modbus rules | DMZ | — |
| Wazuh Manager | `wazuh/wazuh-manager:4.13.0` | SIEM correlation + SOAR automation | IT | 1514, 1515, 15500 |
| OpenSearch | `opensearchproject/opensearch:2.11.1` | Log storage and indexing | IT | 19200 |
| Wazuh Dashboard | `wazuh/wazuh-dashboard:4.13.0` | Security event visualization | IT | 15601 |
| Wazuh Agent | `wazuh/wazuh-agent:4.13.0` | Host-level monitoring (FIM, rootcheck) | IT | — |

## MITRE ATT&CK for ICS Coverage

The lab detects attacks across the full ICS Cyber Kill Chain, with each detection mapped to MITRE ATT&CK for ICS techniques:

| Kill Chain Phase | Technique ID | Technique Name | Detection Rule | Level | Sensor |
|-----------------|-------------|----------------|----------------|-------|--------|
| Reconnaissance | T0802 | Automated Collection | 100102 | 5 | Suricata |
| Reconnaissance | T0846 | Remote System Discovery | 100104 | 6 | Suricata |
| Initial Access | T0886 | Remote Services (SSH) | 100110 | 12 | Wazuh |
| Exploitation | T0866 | Exploitation of Remote Services (SQLi) | 100120 | 12 | Wazuh |
| Exploitation | T0866 | Exploitation of Remote Services (XSS) | 100121 | 10 | Wazuh |
| Exploitation | T0866 | Successful Web Attack (200 OK) | 100122 | 14 | Wazuh |
| Manipulation | T0883 | Change Operating Mode | 100101 | 7 | Suricata |
| Impact | T0813 | Denial of Control | 100103 | 12 | Suricata |
| Persistence | — | File Integrity Change | 550/554 | 7 | Wazuh |
| Response | — | Automated Containment | 651 | 3 | Wazuh |

## Attack Simulation (7 Phases)

The `scripts/attack_sim.sh` script simulates a complete ICS Cyber Kill Chain for live demos:

| Phase | Attack | What It Does | Expected Detection |
|-------|--------|--------------|-------------------|
| 1 | **Reconnaissance** | 5 port probes + Modbus register reads + device fingerprinting | Rules 100102, 100104 |
| 2 | **Initial Access** | 10 SSH brute force attempts with common ICS usernames | Rule 100110 (level 12) |
| 3 | **Web Exploitation** | 4 SQL injection + 3 XSS payloads against OpenPLC HMI | Rules 100120, 100121 |
| 4 | **OT Manipulation** | All 4 Modbus write function codes (FC 0x05/06/0F/10) | Rule 100101 + active response |
| 5 | **Persistence** | Config file tampering (/etc/resolv.conf, /etc/hosts) | FIM rules 550/554 |
| 6 | **Denial of Control** | 10 rapid-fire Modbus write floods | Rule 100103 (level 12) |
| 7 | **Verification** | Automated alert summary across all detection layers | — |

Each phase includes color-coded output, MITRE ATT&CK references, and pause intervals for the detection pipeline to process events.

## Detection Engineering

### Suricata IDS Rules (8 rules)

| SID | Description | Function Code | Category |
|-----|-------------|---------------|----------|
| 9000001 | Write Single Coil | FC 0x05 | Exploitation |
| 9000002 | Write Single Register | FC 0x06 | Exploitation |
| 9000003 | Write Multiple Coils | FC 0x0F | Exploitation |
| 9000004 | Write Multiple Registers | FC 0x10 | Exploitation |
| 9000010 | Read Coils | FC 0x01 | Reconnaissance |
| 9000011 | Read Input Registers | FC 0x04 | Reconnaissance |
| 9000020 | Diagnostics Request | FC 0x08 | Fingerprinting |
| 9000021 | Device Identification | FC 0x2B | Fingerprinting |

### Wazuh Correlation Rules (13 rules)

| Rule ID | Level | Description | Chains From |
|---------|-------|-------------|-------------|
| 100100 | 3 | Base Suricata alert from OT pipeline | 86601 |
| 100101 | 7 | Modbus write operation detected | 100100 |
| 100102 | 5 | Modbus register enumeration (recon) | 100100 |
| 100103 | 12 | Modbus write flooding (Denial of Control) | 100101 (frequency) |
| 100104 | 6 | Device fingerprinting attempt | 100100 |
| 100110 | 12 | SSH brute force against OT infrastructure | 5712 |
| 100111 | 10 | Repeated SSH failures on OT system | 5720 |
| 100120 | 12 | SQL injection against OT HMI | 31104 |
| 100121 | 10 | XSS against OT HMI/SCADA | 31105 |
| 100122 | 14 | Successful web attack (200 OK response) | 31106 |
| 100200 | 3 | Modbus TCP connection observed (Zeek) | json decoder |

See [docs/detection-engineering.md](docs/detection-engineering.md) for decoder chains, false positive analysis, and tuning guidance.

## SOAR Automation

Automated incident response is built into the detection pipeline:

```
Modbus Write Traffic
    → Suricata alert (SID 9000001-9000004)
        → Wazuh rule 100101 fires (level 7)
            → Active Response: firewall-drop on source IP (10 min)
                → Rule 651 logged (containment confirmed)
```

The `firewall-drop` command automatically blocks the attacker's source IP via iptables for 600 seconds. See [docs/active-response.md](docs/active-response.md) for details on the SOAR architecture and OT safety considerations.

## Standards Alignment

| Standard | How This Lab Implements It |
|----------|--------------------------|
| **Purdue Model** | 3 network zones (OT / DMZ / IT) with controlled conduits |
| **NIST SP 800-82** | Boundary protection, continuous monitoring, automated incident response |
| **ISA/IEC 62443** | Zone segmentation, protocol-aware monitoring, security level enforcement |
| **MITRE ATT&CK for ICS** | 10+ techniques detected across the full kill chain |

See [docs/standards-mapping.md](docs/standards-mapping.md) for detailed mapping.

## Repository Structure

```
ot-soc-in-a-box/
├── compose/
│   └── docker-compose.yml          # 8 services, 3 networks, healthchecks
├── config/
│   ├── suricata/rules/
│   │   └── ics-local.rules          # 8 custom Modbus IDS signatures
│   ├── wazuh/
│   │   ├── ossec.conf               # Manager config + active response
│   │   ├── rules/ot-soc_rules.xml   # 13 custom correlation rules
│   │   ├── decoders/                # OT telemetry decoders
│   │   └── shared/                  # Agent configs + CIS benchmarks
│   ├── wazuh-dashboard/
│   │   └── wazuh.yml                # Dashboard → Manager API config
│   └── zeek/
│       └── local.zeek               # JSON logging policy
├── dashboards/
│   └── ot-soc-dashboard.ndjson      # Pre-built OT SOC dashboard
├── docs/
│   ├── architecture.md              # Purdue Model zones + data flow
│   ├── detection-engineering.md     # Decoder chains + tuning guide
│   ├── attack-methodology.md        # Attacker perspective + real-world parallels
│   ├── active-response.md           # SOAR automation + OT safety
│   ├── playbooks.md                 # 6 incident response playbooks
│   ├── standards-mapping.md         # NIST, IEC 62443, MITRE mapping
│   └── validation.md               # Lab validation procedures
├── scripts/
│   ├── start.sh                     # One-command launcher with healthchecks
│   ├── preflight.sh                 # Pre-flight validation
│   ├── attack_sim.sh                # 7-phase ICS Cyber Kill Chain demo
│   ├── test_lab.sh                  # Quick smoke test
│   └── create_dashboard.sh          # Dashboard import
├── .env                             # Credentials (git-ignored)
├── .gitignore
└── LICENSE                          # MIT
```

## Stopping the Lab

```bash
docker compose -f compose/docker-compose.yml down

# Remove stored data too:
docker compose -f compose/docker-compose.yml down -v
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Purdue Model zones, data flow, network segmentation |
| [Detection Engineering](docs/detection-engineering.md) | Rule chains, decoder analysis, false positive tuning |
| [Attack Methodology](docs/attack-methodology.md) | Attacker perspective, real-world ICS incident parallels |
| [Active Response](docs/active-response.md) | SOAR automation, containment strategy, OT safety |
| [Playbooks](docs/playbooks.md) | 6 incident response playbooks with MITRE mapping |
| [Standards Mapping](docs/standards-mapping.md) | NIST SP 800-82, ISA/IEC 62443, Purdue alignment |
| [Validation](docs/validation.md) | Lab health checks and testing procedures |

## License

MIT License. See [LICENSE](LICENSE) for details.
