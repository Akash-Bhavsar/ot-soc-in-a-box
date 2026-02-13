# Standards Mapping

This document maps the lab's capabilities to industry security standards and frameworks used in OT/ICS environments.

## Purdue Enterprise Reference Architecture

The lab implements three Purdue Model zones as separate Docker networks:

| Purdue Level | Lab Zone | Network | Services | Purpose |
|-------------|----------|---------|----------|---------|
| Level 4/5 | IT Zone | `it-zone` | Wazuh Manager, OpenSearch, Dashboard, Agent | SOC operations, alerting, visualization |
| Level 3.5 | OT DMZ | `ot-dmz` | Zeek, Suricata | Protocol analysis, intrusion detection |
| Level 1/2 | OT Zone | `ot-zone` | OpenPLC, Modbus Simulator | Process control, field devices |

**Conduit enforcement:** Zeek and Suricata bridge the OT and DMZ zones to observe traffic, while the Wazuh Manager bridges DMZ and IT to receive telemetry. No IT service has direct network access to OT devices.

## NIST SP 800-82 (Guide to ICS Security)

| NIST SP 800-82 Requirement | Lab Implementation |
|---------------------------|-------------------|
| **5.1** Network segmentation | 3 Docker networks enforce zone boundaries |
| **5.2** Boundary protection | Suricata IDS at OT/DMZ boundary; active response blocks unauthorized access |
| **5.3** Monitoring and detection | Continuous monitoring via Suricata (IDS) + Zeek (NSM) + Wazuh (SIEM) |
| **5.4** Incident response | 6 playbooks with MITRE ATT&CK mapping; automated containment for Playbook #1 |
| **5.5** Access control | SSH brute force detection (100110); web attack detection (100120-122) |
| **6.2.1** Protocol-aware monitoring | Suricata rules match Modbus/TCP function codes at the protocol level |
| **6.2.7** Log management | Centralized logging via Wazuh → OpenSearch with retention and search |

## ISA/IEC 62443 (Industrial Automation Security)

| IEC 62443 Requirement | Lab Implementation |
|----------------------|-------------------|
| **SR 1.1** Human user identification | SSH authentication monitoring (rules 5710, 5712, 100110) |
| **SR 2.8** Auditable events | All OT events logged to OpenSearch with timestamps and source attribution |
| **SR 3.1** Communication integrity | Suricata validates Modbus protocol structure; detects unauthorized function codes |
| **SR 3.3** Security functionality verification | `preflight.sh` validates all security components are running |
| **SR 5.1** Network segmentation | Three separate Docker networks enforcing Purdue zones |
| **SR 5.2** Zone boundary protection | Suricata + active response at zone boundaries |
| **SR 6.1** Audit log accessibility | Wazuh Dashboard provides searchable access to all security events |
| **SR 6.2** Continuous monitoring | Real-time log collection from all telemetry sources |
| **SR 7.6** Network and security config settings | FIM monitors critical configuration files for unauthorized changes |

## MITRE ATT&CK for ICS

Complete mapping of detected techniques:

| Technique ID | Technique Name | Kill Chain Phase | Detection Rules | Confidence |
|-------------|----------------|-----------------|-----------------|------------|
| T0802 | Automated Collection | Reconnaissance | 100102 | High |
| T0846 | Remote System Discovery | Reconnaissance | 100104 | High |
| T0886 | Remote Services | Initial Access | 100110, 100111 | High |
| T0866 | Exploitation of Remote Services | Exploitation | 100120, 100121, 100122 | Medium |
| T0883 | Change Operating Mode | Manipulation | 100101 | High |
| T0831 | Manipulation of Control | Persistence | 550, 554 (FIM) | Medium |
| T0813 | Denial of Control | Impact | 100103 | High |

### Techniques Planned but Not Yet Implemented

| Technique ID | Technique Name | Why Not Yet |
|-------------|----------------|-------------|
| T0814 | Denial of View | Requires HMI display monitoring |
| T0859 | Module Firmware | Requires firmware integrity checking |
| T0808 | Control Device Identification | Partially covered by T0846 |
| T0842 | Network Service Scanning | Partially covered by port probe detection |
| T0855 | Unauthorized Command Message | Covered by T0883 rules |

## NIST Cybersecurity Framework (CSF) Mapping

| CSF Function | CSF Category | Lab Capability |
|-------------|-------------|----------------|
| **Identify** | Asset Management | Zeek passive asset discovery |
| **Protect** | Access Control | SSH monitoring, network segmentation |
| **Detect** | Anomalies & Events | 8 Suricata + 13 Wazuh custom rules |
| **Detect** | Continuous Monitoring | Real-time Suricata + Zeek + Wazuh pipeline |
| **Respond** | Response Planning | 6 documented playbooks |
| **Respond** | Mitigation | Automated firewall-drop active response |
| **Recover** | Recovery Planning | Playbook recovery steps for each scenario |
