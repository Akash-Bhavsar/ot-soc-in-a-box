# Architecture

## Network Zones (Purdue Model)

The lab implements the Purdue Enterprise Reference Architecture with three distinct network zones, each enforced as a separate Docker network:

```
┌─────────────────────────────────────────────────────────────┐
│  Level 4/5 — IT Zone (it-zone network)                      │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Wazuh Manager│  │  OpenSearch  │  │  Wazuh Dashboard  │  │
│  │  (SIEM/SOAR) │  │  (indexing)  │  │  (visualization)  │  │
│  │  :1514,:1515 │  │  :19200      │  │  :15601           │  │
│  └──────┬───────┘  └──────────────┘  └───────────────────┘  │
│         │                                                    │
│  ┌──────┴───────┐                                            │
│  │ Wazuh Agent  │  Host-level monitoring:                    │
│  │              │  - File integrity (FIM)                    │
│  │              │  - Rootkit detection                       │
│  │              │  - System inventory                        │
│  └──────────────┘                                            │
└─────────────────────────────┬───────────────────────────────┘
                              │ conduit (log forwarding)
┌─────────────────────────────┴───────────────────────────────┐
│  Level 3.5 — OT DMZ (ot-dmz network)                        │
│                                                              │
│  ┌──────────────┐           ┌──────────────┐                 │
│  │     Zeek     │           │   Suricata   │                 │
│  │    (NSM)     │           │    (IDS)     │                 │
│  │  conn.log    │           │   eve.json   │                 │
│  └──────┬───────┘           └──────┬───────┘                 │
│         └────────┬─────────────────┘                         │
│          /var/ot/telemetry/ (shared volume)                   │
└─────────────────────────────┬───────────────────────────────┘
                              │ passive tap (mirrored traffic)
┌─────────────────────────────┴───────────────────────────────┐
│  Level 1/2 — OT Zone (ot-zone network)                      │
│                                                              │
│  ┌──────────────┐  ◄── Modbus/TCP ──►  ┌─────────────────┐  │
│  │   OpenPLC    │                       │ Modbus Simulator │  │
│  │  (PLC sim)   │                       │   (OT server)   │  │
│  │  :8080 (HMI) │                       │   :5020         │  │
│  └──────────────┘                       └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Services (8 containers)

| Container | Service | Role | Networks |
|-----------|---------|------|----------|
| `ot-openplc` | OpenPLC Runtime | PLC simulator with Modbus/TCP server + HMI web interface | ot-zone, ot-dmz |
| `ot-modbus-sim` | Modbus Server | Generates realistic OT control traffic for detection testing | ot-zone, ot-dmz |
| `ot-zeek` | Zeek NSM | Protocol-aware network metadata (Modbus, DNS, HTTP, TLS) | ot-zone, ot-dmz |
| `ot-suricata` | Suricata IDS | Deep packet inspection with 8 custom ICS/Modbus rules | ot-zone, ot-dmz |
| `ot-wazuh-manager` | Wazuh Manager | SIEM correlation engine + SOAR active response automation | ot-dmz, it-zone |
| `ot-wazuh-agent` | Wazuh Agent | Host-level monitoring (FIM, rootcheck, syscollector) | it-zone |
| `ot-opensearch` | OpenSearch | Log indexing and search backend | it-zone |
| `ot-wazuh-dashboard` | Wazuh Dashboard | Security event visualization and investigation | it-zone |

## Data Flow

```
1. OT traffic: OpenPLC ◄── Modbus/TCP ──► Modbus Simulator
       │
2. Passive monitoring: Zeek + Suricata observe mirrored traffic
       │
3. Telemetry: Zeek writes conn.log, Suricata writes eve.json
       │                    to shared volume /var/ot/telemetry/
       │
4. Ingestion: Wazuh logcollector reads eve.json + conn.log (JSON format)
       │         Also reads: auth.log (syslog), openplc-access.log (apache)
       │
5. Correlation: Wazuh analysisd applies decoder → rule chains:
       │   eve.json → JSON decoder → 86601 → 100100 → 100101/102/103/104
       │   auth.log → sshd decoder → 5710 → 5712 → 100110
       │   web log  → web-accesslog decoder → 31100 → 31103-31106 → 100120-122
       │
6. Response:
       ├── Alert indexed to OpenSearch → visible in Dashboard
       ├── Active response: firewall-drop on source IP (rule 100101)
       └── Alert logged to /var/ossec/logs/alerts/alerts.json
```

## Shared Volumes

| Volume | Purpose | Consumers |
|--------|---------|-----------|
| `ot_telemetry` | Suricata eve.json + Zeek conn.log | Written by: suricata, zeek. Read by: wazuh-manager |
| `opensearch_data` | OpenSearch indices (persistent) | opensearch |

## Network Segmentation

- **OT Zone** (`ot-zone`): Only PLC simulators and network sensors. No direct access from IT zone.
- **OT DMZ** (`ot-dmz`): Bridge between OT and IT. Zeek and Suricata have interfaces on both zones to observe OT traffic and forward telemetry to IT.
- **IT Zone** (`it-zone`): SOC tools only. Receives processed telemetry, never raw OT traffic.

This segmentation ensures that a compromise of the IT zone (dashboard, OpenSearch) cannot directly access OT devices.

## Security Objectives

1. **Asset inventory**: Zeek passively identifies all communicating OT devices
2. **Baseline monitoring**: Detect deviations from normal Modbus communication patterns
3. **Threat detection**: Suricata signatures + Wazuh correlation for known attack patterns
4. **Automated response**: Block unauthorized Modbus write sources within seconds
5. **Forensic readiness**: All telemetry indexed in OpenSearch for post-incident investigation
